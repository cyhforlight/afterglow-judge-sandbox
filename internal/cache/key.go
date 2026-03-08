package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"afterglow-judge-sandbox/internal/model"
)

// CompileProfile contains the minimal information needed for cache key generation.
type CompileProfile struct {
	ImageRef     string
	BuildCommand []string
}

// CompileKey generates a cache key for compilation based on source code,
// language, compiler image, and build command.
func CompileKey(sourceCode string, lang model.Language, profile CompileProfile) string {
	h := sha256.New()
	h.Write([]byte(sourceCode))
	h.Write([]byte(lang.String()))
	h.Write([]byte(profile.ImageRef))
	h.Write([]byte(strings.Join(profile.BuildCommand, "\x00")))

	return hex.EncodeToString(h.Sum(nil))
}
