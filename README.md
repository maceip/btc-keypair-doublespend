<div align="center">
<img src="docs/imgs/logo.png" width="200">


[📖 Documentation][docs]
</div>

js toolkit for interacting with schnorr sigantures on bitcoin. specifically for testing keys where if they sign messages twice they reveal their secret key.
## Quick Start

### Buid 

- `go mod tidy`
- `GOOS=js GOARCH=wasm go build -o static/main.wasm cmd/wasm/main.go`
- `go run ./cmd/webserver/main.go`
- open your browser, navigate to: http://localhost:3001/
- open dev tools
- `window.jsGenerateKeys()`
<details>
<summary>output</summary>
0
: 
"5da42034f1dbd8de636745f2b225223c3dd90db1184478a984abb7c83955abda"
1
: 
"02fa2ab25ba7d179ddfa023705d26f1579609bd28c63dc47c7d69a9b2d804cee12"
2
: 
"3260c8cff3150ee3a04b4272c470bcb4ea79aed3ba86b5340c3155f47422f29a"
3
: 
"11f853050ca7095201d2def6189acd0074e7979bf86a64384fc1e5229765027e"
4
: 
"cQijAMM8dMKswFdc9pW5eMLAageD1ZtMbZpSXZ4Xsefp5yvvgaaz"
5
: 
"mky1tb7m19whMLG1sTQLXiGdnJwmi8Sioq"
</details>
- `window.jsGenerateTx("5da42034f1dbd8de636745f2b225223c3dd90db1184478a984abb7c83955abda",1,1,"mky1tb7m19whMLG1sTQLXiGdnJwmi8Sioq","c013cd25a9e73b678eb8c8a7304890beb7b29dd18864f0379a562335d3c37a8b",0)`

### Docs
There are canary builds ([Docker Hub](https://hub.docker.com/r/aquasec/trivy/tags?page=1&name=canary), [GitHub](https://github.com/aquasecurity/trivy/pkgs/container/trivy/75776514?tag=canary), [ECR](https://gallery.ecr.aws/aquasecurity/trivy#canary) images and [binaries](https://github.com/aquasecurity/trivy/actions/workflows/canary.yaml)) as generated every push to main branch.

Please be aware: canary builds might have critical bugs, it's not recommended for use in production.

### Reference


Liar, Liar, Coins on Fire!: Penalizing Equivocation By Loss of Bitcoins
https://www.cs.purdue.edu/homes/akate/publications/Non-equivocationWithBitcoinPenalties.pdf


JS Implementation here is build on:
https://docs.babylonchain.io/papers/btc_staking_litepaper.pdf