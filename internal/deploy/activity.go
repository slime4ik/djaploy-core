package deploy

import (
	"context"
	"database/sql"
	"log"
	"strings"
	"time"
)

// Activity feed: events are written when an operation on a project finishes, and read two ways:
// a per-day summary (the grid of squares) and the detail of one day (what exactly happened).
//
// The brightness of a cell is computed by the frontend relative to that user's OWN average day, not
// on an absolute scale: three deploys a day is quiet for one person and a monthly record for another.
// That is why we return the average and the maximum along with the days.

// ActivityDay is one square of the grid.
type ActivityDay struct {
	Date   string `json:"date"` // YYYY-MM-DD
	OK     int    `json:"ok"`
	Failed int    `json:"failed"`
}

// ActivitySummary is the grid for a period plus what the frontend needs to scale brightness.
type ActivitySummary struct {
	Days   []ActivityDay `json:"days"`
	Total  int           `json:"total"`
	Failed int           `json:"failed"`
	Max    int           `json:"max"`    // самый насыщенный день
	Avg    float64       `json:"avg"`    // среднее по ДНЯМ С СОБЫТИЯМИ (пустые не размывают шкалу)
	Streak int           `json:"streak"` // сколько дней подряд с активностью, считая от сегодня
	Best   int           `json:"best"`   // самая длинная серия за период
	Active int           `json:"active"` // дней с активностью
	Year   int           `json:"year"`   // какой год показан
	Years  []int         `json:"years"`  // какие годы вообще можно смотреть (от регистрации)
	From   string        `json:"from"`
	To     string        `json:"to"`
}

// ActivityEvent is one line in a day's detail.
type ActivityEvent struct {
	At      string `json:"at"` // HH:MM
	Kind    string `json:"kind"`
	Status  string `json:"status"`
	Project string `json:"project"`
	Detail  string `json:"detail"`
	Actor   string `json:"actor,omitempty"` // в командной ленте: кто сделал
}

// activityRec is an event queued for writing. The time is taken at the moment of the EVENT, not of
// the insert: the writer may lag by a second, and the day in the grid has to be the right one.
type activityRec struct {
	userID, teamID, depID string
	project, kind, status string
	detail                string
	at                    time.Time
}

// logActivity queues an event. It never blocks the caller: a deploy or an http request must not wait
// on a database insert for the sake of a picture on the dashboard. If the queue is full (the database
// is struggling) we lose a square rather than slow the work down.
// actorID is who pressed the button. For a team project this is NOT the owner of the record: your
// profile should show what you did yourself, not everything done to the project. When it is empty
// (auto deploy on push) we write it to the owner and put the pusher into the detail.
func (s *Service) logActivity(dep *Deployment, actorID, kind, status, detail string) {
	if dep == nil {
		return
	}
	project := dep.Domain
	if project == "" {
		project = dep.Repo
	}
	// The author is unknown and the project is personal, so there is nowhere to write: another person's
	// push has no place in a personal grid, and a personal project has no team feed.
	if actorID == "" && dep.TeamID == "" {
		return
	}
	s.logActivityRaw(actorID, dep.TeamID, dep.ID, project, kind, status, detail)
}

// logActivityRaw does the same for events without a project (revoking server access, for example).
func (s *Service) logActivityRaw(userID, teamID, depID, project, kind, status, detail string) {
	if s.activity == nil || (userID == "" && teamID == "") {
		return
	}
	rec := activityRec{
		userID: userID, teamID: teamID, depID: depID,
		project: project, kind: kind, status: status, detail: detail,
		at: time.Now().UTC(),
	}
	select {
	case s.activity <- rec:
	default:
		log.Printf("activity: очередь переполнена, событие %s потеряно", kind)
	}
}

// activityWriter is the only writer of the feed. A single goroutine worker: inserts go one at a time,
// the database never sees a burst of connections, and callers never wait at all.
func (s *Service) activityWriter() {
	defer close(s.activityDone)
	for rec := range s.activity {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := s.repo.AddActivity(ctx, rec.userID, rec.teamID, rec.depID, rec.project,
			rec.kind, rec.status, rec.detail, rec.at)
		cancel()
		if err != nil {
			log.Printf("activity: запись %s/%s: %v", rec.kind, rec.depID, err)
		}
	}
}

// CloseActivity flushes the tail of the queue when the service shuts down (graceful shutdown).
// We wait no longer than 5 seconds: hanging on shutdown is worse than losing a couple of squares.
func (s *Service) CloseActivity() {
	if s.activity == nil {
		return
	}
	close(s.activity)
	select {
	case <-s.activityDone:
	case <-time.After(5 * time.Second):
		log.Printf("activity: не успели дописать очередь за 5с")
	}
}

// jobKind is what a task becomes in the feed: a normal deploy, a manual redeploy, an auto deploy on
// push, or a rollback. Inside a day that distinction is exactly what matters to the user.
func jobKind(j *job) string {
	switch {
	case j.rollback:
		return "rollback"
	case j.isCD:
		return "cd"
	case j.redeploy:
		return "redeploy"
	default:
		return "deploy"
	}
}

// Activity is the summary for a CALENDAR year. The year is chosen on the frontend; the list of
// available years starts at the signup date (or the team's first event), so we never draw squares for
// a time when the account did not exist.
func (s *Service) Activity(ctx context.Context, userID, teamID string, year int) ActivitySummary {
	if teamID != "" && !s.inTeam(ctx, teamID, userID) {
		return ActivitySummary{Days: []ActivityDay{}, Years: []int{}}
	}
	now := time.Now().UTC()
	start := s.repo.ActivityStart(ctx, userID, teamID)
	if start.After(now) {
		start = now
	}
	if year <= 0 || year > now.Year() || year < start.Year() {
		year = now.Year()
	}

	from := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
	if start.After(from) {
		from = start.Truncate(24 * time.Hour)
	}
	to := time.Date(year, 12, 31, 0, 0, 0, 0, time.UTC)
	if to.After(now) {
		to = now
	}

	rows, err := s.repo.ActivityByDay(ctx, userID, teamID, from, to)
	if err != nil {
		log.Printf("activity: сводка %s: %v", userID, err)
		rows = nil
	}
	byDate := make(map[string]ActivityDay, len(rows))
	for _, r := range rows {
		byDate[r.Date] = r
	}

	out := ActivitySummary{
		Days: []ActivityDay{},
		Year: year,
		From: from.Format("2006-01-02"),
		To:   to.Format("2006-01-02"),
	}
	for y := now.Year(); y >= start.Year(); y-- {
		out.Years = append(out.Years, y)
	}
	streak, best := 0, 0
	for d := from; !d.After(to); d = d.AddDate(0, 0, 1) {
		key := d.Format("2006-01-02")
		day, ok := byDate[key]
		if !ok {
			day = ActivityDay{Date: key}
		}
		out.Days = append(out.Days, day)
		n := day.OK + day.Failed
		out.Total += n
		out.Failed += day.Failed
		if n > out.Max {
			out.Max = n
		}
		if n > 0 {
			out.Active++
			streak++
			if streak > best {
				best = streak
			}
		} else {
			streak = 0
		}
	}
	out.Best = best
	out.Streak = streak
	if out.Active > 0 {
		out.Avg = float64(out.Total) / float64(out.Active)
	}
	return out
}

// ActivityDayEvents returns what exactly happened on a given day (a click on a square).
func (s *Service) ActivityDayEvents(ctx context.Context, userID, teamID, date string) []ActivityEvent {
	day, err := time.Parse("2006-01-02", strings.TrimSpace(date))
	if err != nil {
		return []ActivityEvent{}
	}
	if teamID != "" && !s.inTeam(ctx, teamID, userID) {
		return []ActivityEvent{}
	}
	rows, err := s.repo.ActivityOn(ctx, userID, teamID, day)
	if err != nil {
		log.Printf("activity: день %s: %v", date, err)
		return []ActivityEvent{}
	}
	return rows
}

// inTeam reports whether the user belongs to this team (a team feed is for its members only).
func (s *Service) inTeam(ctx context.Context, teamID, userID string) bool {
	if s.teams == nil {
		return false
	}
	ok, err := s.teams.IsMember(ctx, teamID, userID)
	return err == nil && ok
}

// ── storage ──────────────────────────────────────────────────────────────────

// UserIDByLogin resolves a user id from a GitHub or GitLab login. Needed so a push from a team member
// lands in THEIR personal grid, while a push from an outsider stays in the team feed only.
func (r *Repo) UserIDByLogin(ctx context.Context, login string) string {
	login = strings.TrimSpace(login)
	if login == "" {
		return ""
	}
	var id string
	err := r.db.QueryRowContext(ctx,
		`SELECT id FROM users WHERE username=$1 OR gitlab_username=$1 LIMIT 1`, login).Scan(&id)
	if err != nil {
		return ""
	}
	return id
}

// AddActivity writes a feed event.
func (r *Repo) AddActivity(ctx context.Context, userID, teamID, depID, project, kind, status, detail string, at time.Time) error {
	const q = `INSERT INTO activity (user_id, team_id, deployment_id, project, kind, status, detail, created_at)
	           VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`
	_, err := r.db.ExecContext(ctx, q, nullStr(userID), nullStr(teamID), nullStr(depID), project, kind, status, trimTo(detail, 200), at)
	return err
}

// ActivityByDay is the per-day summary. A personal feed is my events on personal projects; a team one
// is every event of the team (from any member).
func (r *Repo) ActivityByDay(ctx context.Context, userID, teamID string, from, to time.Time) ([]ActivityDay, error) {
	q := `SELECT to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS d,
	             count(*) FILTER (WHERE status <> 'failed'),
	             count(*) FILTER (WHERE status = 'failed')
	      FROM activity
	      WHERE created_at >= $1::timestamptz AND created_at < $2::timestamptz + interval '1 day' AND `
	args := []any{from, to}
	if teamID != "" {
		q += `team_id = $3`
		args = append(args, teamID)
	} else {
		// personal feed: everything this user did, including inside team projects
		q += `user_id = $3`
		args = append(args, userID)
	}
	q += ` GROUP BY d ORDER BY d`

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActivityDay
	for rows.Next() {
		var d ActivityDay
		if err := rows.Scan(&d.Date, &d.OK, &d.Failed); err != nil {
			return out, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ActivityOn returns the events of one day, in time order. In a team feed we also pull the author login.
func (r *Repo) ActivityOn(ctx context.Context, userID, teamID string, day time.Time) ([]ActivityEvent, error) {
	q := `SELECT to_char(a.created_at AT TIME ZONE 'UTC', 'HH24:MI'), a.kind, a.status, a.project, a.detail,
	             COALESCE(u.username, '')
	      FROM activity a
	      LEFT JOIN users u ON u.id = a.user_id
	      WHERE a.created_at >= $1::timestamptz AND a.created_at < $1::timestamptz + interval '1 day' AND `
	args := []any{day}
	if teamID != "" {
		q += `a.team_id = $2`
		args = append(args, teamID)
	} else {
		q += `a.user_id = $2`
		args = append(args, userID)
	}
	q += ` ORDER BY a.created_at DESC`

	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ActivityEvent{}
	for rows.Next() {
		var e ActivityEvent
		if err := rows.Scan(&e.At, &e.Kind, &e.Status, &e.Project, &e.Detail, &e.Actor); err != nil {
			return out, err
		}
		if teamID == "" {
			e.Actor = "" // в личной ленте автор всегда я, не засоряем
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ActivityStart is the earliest date activity can exist: for a personal feed it is the signup date
// (nothing existed before the account), for a team feed it is the team's first event.
func (r *Repo) ActivityStart(ctx context.Context, userID, teamID string) time.Time {
	var t sql.NullTime
	if teamID != "" {
		_ = r.db.QueryRowContext(ctx, `SELECT min(created_at) FROM activity WHERE team_id=$1`, teamID).Scan(&t)
	} else {
		_ = r.db.QueryRowContext(ctx, `SELECT created_at FROM users WHERE id=$1`, userID).Scan(&t)
	}
	if t.Valid {
		return t.Time.UTC()
	}
	return time.Now().UTC()
}

// trimTo keeps a feed detail short (sha, name, reason) instead of a wall of text.
func trimTo(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
