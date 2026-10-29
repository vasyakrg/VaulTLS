package status

import (
	"sync"
	"testing"
)

func TestObserveKeepsLatestPerDestination(t *testing.T) {
	tr := New()
	tr.Observe(Domain{Destination: "/a", Name: "a", Status: "error", Stage: "list"})
	tr.Observe(Domain{Destination: "/a", Name: "a", Status: "ok", Serial: "S1"})

	got := tr.Snapshot()
	if len(got) != 1 {
		t.Fatalf("same destination must overwrite, got %d entries", len(got))
	}
	if got[0].Status != "ok" || got[0].Serial != "S1" || got[0].Stage != "" {
		t.Fatalf("stale fields leaked into the snapshot: %+v", got[0])
	}
}

func TestSnapshotSortedByName(t *testing.T) {
	tr := New()
	tr.Observe(Domain{Destination: "/z", Name: "b.example"})
	tr.Observe(Domain{Destination: "/y", Name: "a.example"})
	tr.Observe(Domain{Destination: "/x", Name: "a.example"}) // same name, second entry

	got := tr.Snapshot()
	if len(got) != 3 {
		t.Fatalf("want 3 entries, got %d", len(got))
	}
	if got[0].Name != "a.example" || got[1].Name != "a.example" || got[2].Name != "b.example" {
		t.Fatalf("snapshot not sorted: %+v", got)
	}
	// Same name: tie-broken by destination, deterministic order for the payload.
	if got[0].Destination > got[1].Destination {
		t.Fatalf("same-name entries must be ordered by destination: %+v", got[:2])
	}
}

func TestConcurrentObserve(t *testing.T) {
	tr := New()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr.Observe(Domain{Destination: "/d", Name: "d", Status: "ok"})
			_ = tr.Snapshot()
		}()
	}
	wg.Wait()
	if len(tr.Snapshot()) != 1 {
		t.Fatal("concurrent writes must not corrupt the map")
	}
}
