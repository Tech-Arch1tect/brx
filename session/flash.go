package session

import (
	"encoding/gob"

	"github.com/labstack/echo/v4"
)

func init() {
	gob.Register([]FlashMessage{})
	gob.Register(FlashMessage{})
}

const (
	FlashMessagesKey = "_flash_messages"
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

func AddFlash(c echo.Context, message string, flashType FlashType) {
	manager := GetManager(c)
	if manager == nil {
		return
	}
	ctx := c.Request().Context()

	var messages []FlashMessage
	if existingMessages := manager.Get(ctx, FlashMessagesKey); existingMessages != nil {
		if msgs, ok := existingMessages.([]FlashMessage); ok {
			messages = msgs
		}
	}

	messages = append(messages, FlashMessage{
		Message: message,
		Type:    flashType,
	})

	manager.Put(ctx, FlashMessagesKey, messages)
}

func AddFlashSuccess(c echo.Context, message string) {
	AddFlash(c, message, FlashSuccess)
}

func AddFlashError(c echo.Context, message string) {
	AddFlash(c, message, FlashError)
}

func AddFlashWarning(c echo.Context, message string) {
	AddFlash(c, message, FlashWarning)
}

func AddFlashInfo(c echo.Context, message string) {
	AddFlash(c, message, FlashInfo)
}

func GetFlashMessages(c echo.Context) []FlashMessage {
	manager := GetManager(c)
	if manager == nil {
		return nil
	}
	ctx := c.Request().Context()

	if messages := manager.Pop(ctx, FlashMessagesKey); messages != nil {
		if msgs, ok := messages.([]FlashMessage); ok {
			return msgs
		}
	}

	return nil
}

func ClearFlashMessages(c echo.Context) {
	manager := GetManager(c)
	if manager == nil {
		return
	}
	ctx := c.Request().Context()
	manager.Pop(ctx, FlashMessagesKey)
}
