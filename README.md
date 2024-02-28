<div align="center">
![btcdouble](https://github.com/maceip/btc-keypair-doublespend/assets/804368/084d1020-ed89-4016-b058-74bad64fe2bc)



[📖 Documentation][cmd]
</div>


js toolkit for interacting with schnorr sigantures on bitcoin. specifically for testing keys that reveal their secret when more than one signature is created.

## Quick Start

### Buid 

- `go mod tidy`
- `GOOS=js GOARCH=wasm go build -o static/main.wasm cmd/wasm/main.go`
- `go run ./cmd/webserver/main.go`
- open your browser, navigate to: http://localhost:3001/
- open dev tools
- `window.jsGenerateKeys()`
- `window.jsGenerateTx(initialSecretKey, amount, fees, address1, unspentTxHash, outIndex)`

<details>
  <summary>window.jsGenerateKeys() output</summary>



0: "5da42034f1dbd8de636745f2b225223c3dd90db1184478a984abb7c83955abda"<br/>
1: "02fa2ab25ba7d179ddfa023705d26f1579609bd28c63dc47c7d69a9b2d804cee12"<br/>
2: "3260c8cff3150ee3a04b4272c470bcb4ea79aed3ba86b5340c3155f47422f29a"<br/>
3: "11f853050ca7095201d2def6189acd0074e7979bf86a64384fc1e5229765027e"<br/>
4: "cQijAMM8dMKswFdc9pW5eMLAageD1ZtMbZpSXZ4Xsefp5yvvgaaz"<br/>
5: "mky1tb7m19whMLG1sTQLXiGdnJwmi8Sioq"<br/>

</details>

<details>
<summary>window.jsGenerateTx() input</summary>
"5da42034f1dbd8de636745f2b225223c3dd90db1184478a984abb7c83955abda",1,1,"mky1tb7m19whMLG1sTQLXiGdnJwmi8Sioq","c013cd25a9e73b678eb8c8a7304890beb7b29dd18864f0379a562335d3c37a8b",0)
</details>

### Docs

bbiab

### Reference


Liar, Liar, Coins on Fire!: Penalizing Equivocation By Loss of Bitcoins
https://www.cs.purdue.edu/homes/akate/publications/Non-equivocationWithBitcoinPenalties.pdf


JS Implementation here is build on:
https://docs.babylonchain.io/papers/btc_staking_litepaper.pdf
