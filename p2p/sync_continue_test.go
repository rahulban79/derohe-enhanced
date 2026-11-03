package p2p

import "testing"

func TestSyncShouldContinue(t *testing.T) {
	for _, c := range []struct {
		name                       string
		round                      int
		before, after, peer_height int64
		exited                     bool
		want                       bool
	}{
		{"r18 restart round 1: 7805170->7805682, peer at 7806053", 1, 7805170, 7805682, 7806053, false, true},
		{"caught up to within the slack", 2, 7805682, 7806045, 7806053, false, false},
		{"exactly caught up", 2, 7805682, 7806053, 7806053, false, false},
		{"no progress (failed request) never loops", 1, 7805170, 7805170, 7806053, false, false},
		{"went backwards (reorg) never loops", 1, 7805170, 7805100, 7806053, false, false},
		{"peer gone", 1, 7805170, 7805682, 7806053, true, false},
		{"round cap", SYNC_CONTINUE_MAX_ROUNDS, 1, 513, 1 << 30, false, false},
		{"round below the cap continues", SYNC_CONTINUE_MAX_ROUNDS - 1, 1, 513, 1 << 30, false, true},
		{"slow peer: 1 block per round stops", 1, 7805170, 7805171, 7806053, false, false},
		{"slow peer: just under the progress floor stops", 1, 7805170, 7805170 + SYNC_CONTINUE_MIN_PROGRESS - 1, 7806053, false, false},
		{"progress floor met continues", 1, 7805170, 7805170 + SYNC_CONTINUE_MIN_PROGRESS, 7806053, false, true},
	} {
		if got := sync_should_continue(c.round, c.before, c.after, c.peer_height, c.exited); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
	if SYNC_CONTINUE_MAX_ROUNDS > 16 {
		t.Errorf("SYNC_CONTINUE_MAX_ROUNDS %d: one peer must not hold trigger_sync for more than ~8k blocks", SYNC_CONTINUE_MAX_ROUNDS)
	}
}
