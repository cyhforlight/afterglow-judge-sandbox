package service

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

const defaultCheckerName = "default"

var builtinCheckers = []string{
	defaultCheckerName,
	"ncmp",
	"wcmp",
	"fcmp",
	"yesno",
	"nyesno",
	"lcmp",
	"hcmp",
	"rcmp4",
	"rcmp6",
	"rcmp9",
}

// BuiltinCheckerNames returns the bundled checker short names.
func BuiltinCheckerNames() []string {
	return slices.Clone(builtinCheckers)
}

// CheckerPolicy resolves request checker names into bundled storage keys.
type CheckerPolicy struct {
	defaultChecker string
	allowed        []string
	allowedSet     map[string]struct{}
}

// NewCheckerPolicy creates a validated checker policy.
func NewCheckerPolicy(defaultChecker string, allowedCheckers []string) (*CheckerPolicy, error) {
	defaultChecker = strings.TrimSpace(defaultChecker)
	if defaultChecker == "" {
		defaultChecker = defaultCheckerName
	}

	if len(allowedCheckers) == 0 {
		allowedCheckers = BuiltinCheckerNames()
	}

	allowed := make([]string, 0, len(allowedCheckers))
	allowedSet := make(map[string]struct{}, len(allowedCheckers))
	for _, raw := range allowedCheckers {
		name := strings.TrimSpace(raw)
		if err := validateCheckerShortName(name); err != nil {
			return nil, fmt.Errorf("allowed checker %q: %w", raw, err)
		}
		if _, exists := allowedSet[name]; exists {
			continue
		}
		allowed = append(allowed, name)
		allowedSet[name] = struct{}{}
	}

	policy := &CheckerPolicy{
		defaultChecker: defaultChecker,
		allowed:        allowed,
		allowedSet:     allowedSet,
	}
	if err := policy.ValidateConfig(); err != nil {
		return nil, err
	}

	return policy, nil
}

// ValidateConfig verifies checker policy configuration at startup.
func (p *CheckerPolicy) ValidateConfig() error {
	if p == nil {
		return errors.New("checker policy is required")
	}
	if err := validateCheckerShortName(p.defaultChecker); err != nil {
		return fmt.Errorf("default checker %q: %w", p.defaultChecker, err)
	}
	if len(p.allowed) == 0 {
		return errors.New("allowed checkers must not be empty")
	}
	if _, ok := p.allowedSet[p.defaultChecker]; !ok {
		return fmt.Errorf("default checker %q is not in allowed checkers %v", p.defaultChecker, p.allowed)
	}

	return nil
}

// Resolve converts a request checker into a validated bundled checker short name.
func (p *CheckerPolicy) Resolve(raw string) (string, error) {
	if p == nil {
		return "", errors.New("checker policy is required")
	}

	name := strings.TrimSpace(raw)
	if name == "" {
		return p.defaultChecker, nil
	}
	if err := validateCheckerShortName(name); err != nil {
		return "", err
	}
	if _, ok := p.allowedSet[name]; !ok {
		return "", fmt.Errorf("checker %q is not allowed (allowed: %v)", name, p.allowed)
	}

	return name, nil
}

// StorageKey returns the internal storage key for a checker short name.
func (p *CheckerPolicy) StorageKey(shortName string) string {
	return fmt.Sprintf("checkers/%s.cpp", shortName)
}

func validateCheckerShortName(name string) error {
	if name == "" {
		return errors.New("checker name must not be empty")
	}
	if strings.ContainsAny(name, `/\.`) {
		return fmt.Errorf("checker %q must be a builtin short name", name)
	}
	for _, r := range name {
		if !unicode.IsLower(r) && !unicode.IsDigit(r) {
			return fmt.Errorf("checker %q must be a builtin short name", name)
		}
	}

	return nil
}
