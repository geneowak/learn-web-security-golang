package uploads

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/geneowak/learn-web-security/internal/httpx"
)

const signedDownloadTTL = 5 * time.Minute

func CreateSignedDownloadPath(signingKey [32]byte, fileID int64, now time.Time) string {
	expires := now.Unix() + int64(signedDownloadTTL.Seconds())
	signature := signDownload(signingKey, fileID, expires)
	return fmt.Sprintf("/files/%d/signed-download?expires=%d&signature=%s", fileID, expires, signature)
}

func VerifySignedDownload(signingKey [32]byte, fileID int64, expiresValue, signature string, now time.Time) bool {
	if expiresValue == "" || strings.Trim(expiresValue, "0123456789") != "" || len(signature) != 64 {
		return false
	}
	expires, ok := httpx.ParseSafeInteger(expiresValue)
	if !ok {
		return false
	}
	mac := signDownload(signingKey, fileID, expires)
	if expires <= now.Unix() || subtle.ConstantTimeCompare([]byte(mac), []byte(signature)) != 1 {
		return false
	}
	return true
}

func signDownload(signingKey [32]byte, fileID, expires int64) string {
	mac := hmac.New(sha256.New, signingKey[:])
	fmt.Fprint(mac, "GET\n/files/%d/signed-download\n%d", fileID, expires)
	return hex.EncodeToString(mac.Sum(nil))
}
