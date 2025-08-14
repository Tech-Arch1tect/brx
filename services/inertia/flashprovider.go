package inertia

import (
	"context"
	"encoding/gob"

	gonertia "github.com/romsar/gonertia/v2"
	"github.com/tech-arch1tect/brx/session"
)

func init() {

	gob.Register(gonertia.ValidationErrors{})
}

type SCSFlashProvider struct{}

func NewSCSFlashProvider() *SCSFlashProvider {
	return &SCSFlashProvider{}
}

func (p *SCSFlashProvider) FlashErrors(ctx context.Context, errors gonertia.ValidationErrors) error {

	if manager := session.GetManagerFromContext(ctx); manager != nil {
		manager.Put(ctx, "validation_errors", errors)
	}
	return nil
}

func (p *SCSFlashProvider) GetErrors(ctx context.Context) (gonertia.ValidationErrors, error) {
	if manager := session.GetManagerFromContext(ctx); manager != nil {

		if errors := manager.Pop(ctx, "validation_errors"); errors != nil {
			if validationErrors, ok := errors.(gonertia.ValidationErrors); ok {
				return validationErrors, nil
			}
		}
	}
	return nil, nil
}

func (p *SCSFlashProvider) FlashClearHistory(ctx context.Context) error {
	if manager := session.GetManagerFromContext(ctx); manager != nil {
		manager.Put(ctx, "clear_history", true)
	}
	return nil
}

func (p *SCSFlashProvider) ShouldClearHistory(ctx context.Context) (bool, error) {
	if manager := session.GetManagerFromContext(ctx); manager != nil {

		if clearHistory := manager.Pop(ctx, "clear_history"); clearHistory != nil {
			if shouldClear, ok := clearHistory.(bool); ok {
				return shouldClear, nil
			}
		}
	}
	return false, nil
}
