package hotp

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateAuthQR(t *testing.T) {
	file, err := os.Create("testqr.jpeg")

	require.NoError(t, err)

	defer file.Close()
	auth := Auth{
		Label: "Example",
		User:"demo@demo.com",
		Key:"JBSWY3DPEHPK3PXP",
		Digits: 6,
		Period: 30,
	}
	err = GenerateAuthQR(auth, file)
	assert.NoError(t, err)
}
func TestGenerateURL(t *testing.T){
	auth := Auth{
		Label: "Example 2",
		User:"demo@demo.com",
		Key:"JBSWY3DPEHPK3PXP",
		Digits: 6,
		Period: 30,
	}
	url := "otpauth://totp/Example 2:demo@demo.com?secret=JBSWY3DPEHPK3PXP&issuer=Example 2&digits=6&period=30"

	result := GenerateURL(auth)

	assert.Equal(t, url, result)
}

func TestGenerateQR(t *testing.T) {
	file, err := os.Create("testqr.jpeg")

	require.NoError(t, err)

	defer file.Close()

	message := "https://github.com/dannywolfmx"
	err = GenerateQR(message, file)

	assert.NoError(t, err)
}

func TestGetTOTPToken(t *testing.T){
	auth := Auth{
		Label: "Example",
		User:"demo@demo.com",
		Key:"JBSWY3DPEHPK3PXP",
		Digits: 6,
		Period: 30,
	}

	result, err := GetTOTPToken(auth)
	assert.NoError(t, err)
	assert.Len(t, result, auth.Digits)
	t.Fatal(result)
}

func TestGetHOTPToken(t *testing.T) {
	//Secret message and duration

	unixTime := int64(1628726047)
	auth := Auth{
		Label: "Example",
		User:"demo@demo.com",
		Key:"JBSWY3DPEHPK3PXP",
		Digits: 6,
		Period: 30,
	}
	duration := unixTime / auth.Period
	expectedResult := "554427"

	result, err := GetHOTPToken(auth, duration) 

	assert.NoError(t, err)
	assert.Equal(t,len(expectedResult), len(result))
	assert.Equal(t,expectedResult, result)
}

func TestNormalizeOTP(t *testing.T){

	lenght := 6

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
		result := normalizeOTP(key, lenght)
		assert.Equal(t, value, result)
	}
}