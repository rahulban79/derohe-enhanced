package rwc

// MaxMessageSize bounds one incoming websocket message on the JSON-RPC servers. gorilla/websocket's
// default read limit is 0 = unlimited, and every server upgrades with CheckOrigin=true, so any web page
// open in the user's browser could stream one endless message into derod/wallet memory. The largest
// legitimate request is a hex-encoded SubmitBlock: 2 x STARGATE_HE_MAX_BLOCK_SIZE (10.25 MiB) plus framing.
const MaxMessageSize = 32 << 20
