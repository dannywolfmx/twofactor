package hotp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateAuthQR(t *testing.T) {
	auth := Auth{
		Label: "Example",
		User:"demo@google.com",
		Key:"JBSWY3DPEHPK3PXP",
		Digits: 6,
		Period: 30,
	}
	err := GenerateAuthQR(auth)
	assert.NoError(t, err)
}
func TestGenerateURL(t *testing.T){
	auth := Auth{
		Label: "Example 2",
		User:"demo@google.com",
		Key:"JBSWY3DPEHPK3PXP",
		Digits: 6,
		Period: 30,
	}
	url := "otpauth://totp/Example 2:demo@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example 2&digits=6&period=30"

	result := GenerateURL(auth)

	assert.Equal(t, url, result)
}

func TestGenerateQR(t *testing.T) {

	message := "https://github.com/dannywolfmx"
	err := GenerateQR(message)

	assert.NoError(t, err)

}

func TestGetHOTPToken(t *testing.T) {
	//Secret message and duration

	message := "dummySECRETdummy"
	intervalInSeconds := int64(30)
	unixTime := int64(1628726047)
	duration := unixTime / intervalInSeconds
	expectedResult := "427727"

	result, err := GetHOTPToken(message, duration) 

	assert.NoError(t, err)
	assert.Equal(t,len(expectedResult), len(result))
	assert.Equal(t,expectedResult, result)
}

func TestNormalizeOTP(t *testing.T){

	//Input - ExpectedOutput
	testData := map[string]string{
		"1":"000001",
		"11":"000011",
		"111":"000111",
		"1111":"001111",
		"11111":"011111",
		"111111":"111111",
	}


	for key, value := range testData{
		result := normalizeOTP(key)
		assert.Equal(t, value, result)
	}
}