<h1 align="center">
  <br>
  Pion RTP
  <br>
</h1>
<h4 align="center">A Go implementation of RTP</h4>
<p align="center">
  <a href="https://pion.ly"><img src="https://img.shields.io/badge/pion-rtp-gray.svg?longCache=true&colorB=brightgreen" alt="Pion RTP"></a>
  <a href="https://sourcegraph.com/github.com/pion/rtp?badge"><img src="https://sourcegraph.com/github.com/pion/rtp/-/badge.svg" alt="Sourcegraph Widget"></a>
  <a href="https://discord.gg/PngbdqpFbt"><img src="https://img.shields.io/badge/join-us%20on%20discord-gray.svg?longCache=true&logo=discord&colorB=brightblue" alt="join us on Discord"></a> <a href="https://bsky.app/profile/pion.ly"><img src="https://img.shields.io/badge/follow-us%20on%20bluesky-gray.svg?longCache=true&logo=bluesky&colorB=brightblue" alt="Follow us on Bluesky"></a>
  <br>
  <img alt="GitHub Workflow Status" src="https://img.shields.io/github/actions/workflow/status/pion/rtp/test.yaml">
  <a href="https://pkg.go.dev/github.com/pion/rtp"><img src="https://pkg.go.dev/badge/github.com/pion/rtp.svg" alt="Go Reference"></a>
  <a href="https://codecov.io/gh/pion/rtp"><img src="https://codecov.io/gh/pion/rtp/branch/master/graph/badge.svg" alt="Coverage Status"></a>
  <a href="https://goreportcard.com/report/github.com/pion/rtp"><img src="https://goreportcard.com/badge/github.com/pion/rtp" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>
<br>

### Implemented
- [RFC 3550](https://www.rfc-editor.org/rfc/rfc3550.html) — RTP: A Transport Protocol for Real-Time Applications
- [RFC 8285](https://www.rfc-editor.org/rfc/rfc8285.html) — A General Mechanism for RTP Header Extensions

#### Header Extensions
- [RFC 6464](https://www.rfc-editor.org/rfc/rfc6464.html) — RTP Header Extension for Client-to-Mixer Audio Level Indication
- [draft-holmer-rmcat-transport-wide-cc-extensions-01](https://datatracker.ietf.org/doc/html/draft-holmer-rmcat-transport-wide-cc-extensions-01) — Transport-Wide Congestion Control
- [Absolute Send Time](https://webrtc.googlesource.com/src/%2B/refs/heads/main/docs/native-code/rtp-hdrext/abs-send-time/README.md) (WebRTC extension, non-RFC)
- [Absolute Capture Time](https://webrtc.googlesource.com/src/%2B/refs/heads/main/docs/native-code/rtp-hdrext/abs-capture-time/README.md) (WebRTC extension, non-RFC)
- [Playout Delay](https://webrtc.googlesource.com/src/%2B/main/docs/native-code/rtp-hdrext/playout-delay/README.md) (WebRTC extension, non-RFC)
- [Video Layers Allocation](https://webrtc.googlesource.com/src/+/refs/heads/main/docs/native-code/rtp-hdrext/video-layers-allocation00) (WebRTC extension, non-RFC)

#### Codecs
- [RFC 3551](https://www.rfc-editor.org/rfc/rfc3551.html) — RTP Profile for PCMA/PCMU (G.711) and G.722 Audio
- [RFC 6184](https://www.rfc-editor.org/rfc/rfc6184.html) — RTP Payload Format for H.264 Video
- [RFC 7587](https://www.rfc-editor.org/rfc/rfc7587.html) — RTP Payload Format for the Opus Audio Codec
- [RFC 7741](https://www.rfc-editor.org/rfc/rfc7741.html) — RTP Payload Format for VP8 Video
- [draft-ietf-payload-vp9](https://datatracker.ietf.org/doc/draft-ietf-payload-vp9/) — RTP Payload Format for VP9 Video
- [draft-ietf-avtcore-rtp-hevc](https://datatracker.ietf.org/doc/draft-ietf-avtcore-rtp-hevc/) — RTP Payload Format for H.265 Video
- [AV1 RTP Payload Specification](https://aomediacodec.github.io/av1-rtp-spec/v1.0.0.html) — RTP Payload Format for AV1 Video

### Roadmap
The library is used as a part of our WebRTC implementation. Please refer to that [roadmap](https://github.com/pion/webrtc/issues/9) to track our major milestones.

### Community
Pion has an active community on the [Discord](https://discord.gg/PngbdqpFbt).

Follow the [Pion Bluesky](https://bsky.app/profile/pion.ly) or [Pion Twitter](https://twitter.com/_pion) for project updates and important WebRTC news.

We are always looking to support **your projects**. Please reach out if you have something to build!
If you need commercial support or don't want to use public methods you can contact us at [team@pion.ly](mailto:team@pion.ly)

### Contributing
Check out the [contributing wiki](https://github.com/pion/webrtc/wiki/Contributing) to join the group of amazing people making this project possible

### License
MIT License - see [LICENSE](LICENSE) for full text
