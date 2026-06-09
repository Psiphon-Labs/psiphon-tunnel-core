<h1 align="center">
  <br>
  Pion SCTP
  <br>
</h1>
<h4 align="center">A Go implementation of SCTP</h4>
<p align="center">
  <a href="https://pion.ly"><img src="https://img.shields.io/badge/pion-sctp-gray.svg?longCache=true&colorB=brightgreen" alt="Pion SCTP"></a>
  <a href="https://discord.gg/PngbdqpFbt"><img src="https://img.shields.io/badge/join-us%20on%20discord-gray.svg?longCache=true&logo=discord&colorB=brightblue" alt="join us on Discord"></a> <a href="https://bsky.app/profile/pion.ly"><img src="https://img.shields.io/badge/follow-us%20on%20bluesky-gray.svg?longCache=true&logo=bluesky&colorB=brightblue" alt="Follow us on Bluesky"></a>
  <br>
  <img alt="GitHub Workflow Status" src="https://img.shields.io/github/actions/workflow/status/pion/sctp/test.yaml">
  <a href="https://pkg.go.dev/github.com/pion/sctp"><img src="https://pkg.go.dev/badge/github.com/pion/sctp.svg" alt="Go Reference"></a>
  <a href="https://codecov.io/gh/pion/sctp"><img src="https://codecov.io/gh/pion/sctp/branch/master/graph/badge.svg" alt="Coverage Status"></a>
  <a href="https://goreportcard.com/report/github.com/pion/sctp"><img src="https://goreportcard.com/badge/github.com/pion/sctp" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
</p>
<br>

### Implemented
- [RFC 6525](https://www.rfc-editor.org/rfc/rfc6525.html) — Stream Control Transmission Protocol (SCTP) Stream Reconfiguration
- [RFC 3758](https://www.rfc-editor.org/rfc/rfc3758.html) — Stream Control Transmission Protocol (SCTP) Partial Reliability Extension
- [RFC 5061](https://www.rfc-editor.org/rfc/rfc5061.html) — Stream Control Transmission Protocol (SCTP) Dynamic Address Reconfiguration
- [RFC 4895](https://www.rfc-editor.org/rfc/rfc4895.html) — Authenticated Chunks for the Stream Control Transmission Protocol (SCTP)
- [RFC 1982](https://www.rfc-editor.org/rfc/rfc1982.html) — Serial Number Arithmetic

### Partial implementations
Pion only implements the subset of RFC 4960 that is required for WebRTC.

- [RFC 4960](https://www.rfc-editor.org/rfc/rfc4960.html) — Stream Control Transmission Protocol [Obsoleted by 9260, above]
- [RFC 2960](https://www.rfc-editor.org/rfc/rfc2960.html) — Stream Control Transmission Protocol [Obsoleted by 4960, above]

The update to [RFC 9260](https://www.rfc-editor.org/rfc/rfc9260) — Stream Control Transmission Protocol is currently a [work in progress](https://github.com/pion/sctp/issues/402).

### Potential future implementations
Ideally, we would like to add the following features as part of a [v2 refresh](https://github.com/pion/sctp/issues/314):

Feature | Reference | Progress
--- | --- | ---
RACK (tail loss probing) | [Paper](https://icnp20.cs.ucr.edu/proceedings/nipaa/RACK%20for%20SCTP.pdf), [Comment](https://github.com/pion/sctp/issues/206#issuecomment-968265853)| [In review](https://github.com/pion/sctp/pull/390)
Adaptive burst mitigation | [Paper, see section 5A](https://icnp20.cs.ucr.edu/proceedings/nipaa/RACK%20for%20SCTP.pdf)| [In review](https://github.com/pion/sctp/pull/394)
Update to RFC 9260 | [Parent issue](https://github.com/pion/sctp/issues/402) | [In progress](https://github.com/pion/sctp/issues/402)
Implement RFC 8260 | [Issue](https://github.com/pion/sctp/issues/435) | In progress (no PR available yet)
Blocking writes | [1](https://github.com/pion/sctp/issues/77), [2](https://github.com/pion/sctp/issues/357) | [Potentially in progress](https://github.com/pion/sctp/issues/357#issuecomment-3382050767)
association.listener (and better docs) | [1](https://github.com/pion/sctp/issues/74), [2](https://github.com/pion/sctp/issues/173) | Not started, [blocked by above](https://github.com/pion/sctp/issues/74#issuecomment-545550714)

RFCs of interest:
- [RFC 9438](https://datatracker.ietf.org/doc/rfc9438/) as it addresses the low utilization problem of [RFC 4960](https://www.rfc-editor.org/rfc/rfc4960.html) in fast long-distance networks as mentioned [here](https://github.com/pion/sctp/issues/218#issuecomment-3329690797).

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
