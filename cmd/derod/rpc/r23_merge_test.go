package rpc

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lesismal/nbio/nbhttp/websocket"
)

// r23 merge: a ban covers every session of the key. A second open session of a banned key gets no verification, and
// the ban lists exactly the key's other remote sessions for closing.
func TestR23GetworkBannedKeyOtherSessions(t *testing.T) {
	key := "198.51.100.77"
	c1, c2, c3, c4 := new(websocket.Conn), new(websocket.Conn), new(websocket.Conn), new(websocket.Conn)
	s1 := &user_session{limit_key: key}
	s2 := &user_session{limit_key: key}
	s3 := &user_session{limit_key: "198.51.100.78"}
	s4 := &user_session{limit_key: key, loopback: true}
	for _, x := range []struct {
		c *websocket.Conn
		s *user_session
	}{{c1, s1}, {c2, s2}, {c3, s3}, {c4, s4}} {
		getwork_register(x.c, x.s)
		defer getwork_unregister(x.c)
	}
	now := time.Now()
	if getwork_session_refused(s2, now) {
		t.Fatal("an unbanned session must be verified")
	}
	getwork_ban(key, now)
	defer func() {
		getwork_bans.mu.Lock()
		delete(getwork_bans.m, key)
		getwork_bans.mu.Unlock()
	}()
	if !getwork_session_refused(s2, now.Add(time.Second)) {
		t.Fatal("a second open session of a banned key was still verified")
	}
	if getwork_session_refused(s3, now) || getwork_session_refused(s4, now) {
		t.Fatal("another key, or a loopback session, must not be refused")
	}
	got := sessions_of_key(key, c1)
	if len(got) != 1 || got[0] != c2 {
		t.Fatalf("sessions to close for the banned key: %v (want only c2)", got)
	}
}

// r23 merge: OnMessage refuses shares of a session whose key is banned (not only of the session that earned the ban),
// and the ban closes the key's other sessions.
func TestR23GetworkBanWired(t *testing.T) {
	for file, want := range map[string]string{
		"websocket_getwork_server.go": "if getwork_session_refused(sess, time.Now()) {",
		"getwork_guard.go":            "for _, o := range sessions_of_key(sess.limit_key, c) {",
	} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), want) {
			t.Errorf("%s: missing %q", file, want)
		}
	}
}
