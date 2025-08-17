package session

import (
	"github.com/labstack/echo/v4"
)

const (
	FlashKey     = "_flash"
	FlashTypeKey = "_flash_type"
)

type FlashType string

const (
	FlashSuccess FlashType = "success"
	FlashError   FlashType = "error"
	FlashWarning FlashType = "warning"
	FlashInfo    FlashType = "info"
)

type FlashMessage struct {
	Message string    `json:"message"`
	Type    FlashType `json:"type"`
}

func SetFlash(c echo.Context, message string) {
	SetFlashWithType(c, message, FlashError)
}

func SetFlashWithType(c echo.Context, message string, flashType FlashType) {
	manager := GetManager(c)
	if manager == nil {
		return
	}
	ctx := c.Request().Context()
	manager.Put(ctx, FlashKey, message)
	manager.Put(ctx, FlashTypeKey, string(flashType))
}

func SetFlashSuccess(c echo.Context, message string) {
	SetFlashWithType(c, message, FlashSuccess)
}

func SetFlashError(c echo.Context, message string) {
	SetFlashWithType(c, message, FlashError)
}

func SetFlashWarning(c echo.Context, message string) {
	SetFlashWithType(c, message, FlashWarning)
}

func SetFlashInfo(c echo.Context, message string) {
	SetFlashWithType(c, message, FlashInfo)
}

func GetFlash(c echo.Context) string {
	manager := GetManager(c)
	if manager == nil {
		return ""
	}
	ctx := c.Request().Context()
	flash := manager.Pop(ctx, FlashKey)

	manager.Pop(ctx, FlashTypeKey)
	if flash == nil {
		return ""
	}
	if msg, ok := flash.(string); ok {
		return msg
	}
	return ""
}

func GetFlashWithType(c echo.Context) *FlashMessage {
	manager := GetManager(c)
	if manager == nil {
		return nil
	}
	ctx := c.Request().Context()
	flash := manager.Pop(ctx, FlashKey)
	flashType := manager.Pop(ctx, FlashTypeKey)

	if flash == nil {
		return nil
	}

	msg, ok := flash.(string)
	if !ok {
		return nil
	}

	msgType := FlashError
	if flashType != nil {
		if typeStr, ok := flashType.(string); ok {
			msgType = FlashType(typeStr)
		}
	}

	return &FlashMessage{
		Message: msg,
		Type:    msgType,
	}
}
