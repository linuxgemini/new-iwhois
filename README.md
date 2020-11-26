# new-iwhois

New Generation Interactive WHOIS

It's a gimmick name, but hey it explains what it is.

A "small" JavaScript applet to serve a web WHOIS endpoint. Has simple Redis caching and request ratelimiting.

## Requirements

  - Node.js (>=12)
  - Redis server with 2 adjacent available databases (For example, if you define 5 in the config, 5 and 6 is going to be used)

## Usage

Copy `config.json.example` as `config.json` and modify it.

You can then run `index.js` with your favourite daemonizer I Guess™.

## License

Its AGPLv3.

## Running Hosts

  - [w.iye.be][wiye] \(Hosted by [linuxgemini][]\)

## Author(s)

  - [İlteriş Yağıztegin Eroğlu \(linuxgemini\)][linuxgemini]


[linuxgemini]: https://linuxgemini.space
[wiye]: https://w.iye.be
