package deploy

import "testing"

func TestParseServerStats(t *testing.T) {
	lines := []string{
		"DISK 41152000 12345600 31%",
		"MEM 2048000 1400000",
		"LOAD 0.42",
		"CPUS 2",
		"CT shop-web-1|running|Up 3 hours",
		"CT shop-db-1|exited|Exited (0) 5 minutes ago",
	}
	st := parseServerStats(lines)

	if st.DiskUsedPct != 31 {
		t.Fatalf("disk pct: expected 31, got %d", st.DiskUsedPct)
	}
	if st.CPUs != 2 || st.Load1 != "0.42" {
		t.Fatalf("cpus/load: %d %q", st.CPUs, st.Load1)
	}
	// we report available memory, so used% = (total-avail)/total
	if st.MemUsedPct != 31 { // (2048000-1400000)/2048000 ≈ 31%
		t.Fatalf("mem used pct: expected about 31, got %d", st.MemUsedPct)
	}
	if st.MemAvail != "1.3 ГБ" {
		t.Fatalf("mem avail human: got %q", st.MemAvail)
	}
	if len(st.Containers) != 2 {
		t.Fatalf("containers: expected 2, got %d", len(st.Containers))
	}
	if st.Containers[0].Name != "shop-web-1" || st.Containers[0].State != "running" {
		t.Fatalf("first container parsed wrong: %+v", st.Containers[0])
	}
	if st.Containers[1].State != "exited" {
		t.Fatalf("second container: expected exited, got %q", st.Containers[1].State)
	}
}

func TestHumanKB(t *testing.T) {
	cases := map[int64]string{
		512:      "512 КБ",
		2048:     "2 МБ",
		1572864:  "1.5 ГБ",
		41152000: "39.2 ГБ",
	}
	for kb, want := range cases {
		if got := humanKB(kb); got != want {
			t.Errorf("humanKB(%d): expected %q, got %q", kb, want, got)
		}
	}
}
