# twofactor
Two factor authenticator in go

Following the instruction from [gojek.io](https://www.gojek.io/blog/a-diy-two-factor-authenticator-in-golang)


Example of qr with the next data:
```go
	auth := Auth{
		Label: "Example",
		User:"demo@demo.com",
		Key:"JBSWY3DPEHPK3PXP",
		Digits: 6,
		Period: 30,
	}
```

<img src="./hotp/testqr.jpeg" width="200" height="200">
