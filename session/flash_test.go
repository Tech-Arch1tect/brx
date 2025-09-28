package session

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddFlash(t *testing.T) {
	t.Run("add single flash message", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		AddFlash(c, "Test message", FlashSuccess)

		ctx := c.Request().Context()
		messages := manager.Get(ctx, FlashMessagesKey)
		assert.NotNil(t, messages)

		flashMessages := messages.([]FlashMessage)
		assert.Len(t, flashMessages, 1)
		assert.Equal(t, "Test message", flashMessages[0].Message)
		assert.Equal(t, FlashSuccess, flashMessages[0].Type)
	})

	t.Run("add multiple flash messages", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		AddFlash(c, "Success message", FlashSuccess)
		AddFlash(c, "Error message", FlashError)

		ctx := c.Request().Context()
		messages := manager.Get(ctx, FlashMessagesKey)
		flashMessages := messages.([]FlashMessage)

		assert.Len(t, flashMessages, 2)
		assert.Equal(t, "Success message", flashMessages[0].Message)
		assert.Equal(t, FlashSuccess, flashMessages[0].Type)
		assert.Equal(t, "Error message", flashMessages[1].Message)
		assert.Equal(t, FlashError, flashMessages[1].Type)
	})

	t.Run("without session manager", func(t *testing.T) {
		c, _ := createTestContext()

		AddFlash(c, "Test message", FlashSuccess)
	})
}

func TestFlashTypeHelpers(t *testing.T) {
	c, _ := createTestContext()
	manager := setupContextWithSessionManager(c)

	t.Run("AddFlashSuccess", func(t *testing.T) {
		AddFlashSuccess(c, "Success message")

		ctx := c.Request().Context()
		messages := manager.Get(ctx, FlashMessagesKey).([]FlashMessage)
		assert.Equal(t, FlashSuccess, messages[0].Type)
		assert.Equal(t, "Success message", messages[0].Message)
	})

	t.Run("AddFlashError", func(t *testing.T) {
		AddFlashError(c, "Error message")

		ctx := c.Request().Context()
		messages := manager.Get(ctx, FlashMessagesKey).([]FlashMessage)
		lastMessage := messages[len(messages)-1]
		assert.Equal(t, FlashError, lastMessage.Type)
		assert.Equal(t, "Error message", lastMessage.Message)
	})

	t.Run("AddFlashWarning", func(t *testing.T) {
		AddFlashWarning(c, "Warning message")

		ctx := c.Request().Context()
		messages := manager.Get(ctx, FlashMessagesKey).([]FlashMessage)
		lastMessage := messages[len(messages)-1]
		assert.Equal(t, FlashWarning, lastMessage.Type)
		assert.Equal(t, "Warning message", lastMessage.Message)
	})

	t.Run("AddFlashInfo", func(t *testing.T) {
		AddFlashInfo(c, "Info message")

		ctx := c.Request().Context()
		messages := manager.Get(ctx, FlashMessagesKey).([]FlashMessage)
		lastMessage := messages[len(messages)-1]
		assert.Equal(t, FlashInfo, lastMessage.Type)
		assert.Equal(t, "Info message", lastMessage.Message)
	})
}

func TestGetFlashMessages(t *testing.T) {
	t.Run("get existing messages", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		ctx := c.Request().Context()
		expectedMessages := []FlashMessage{
			{Message: "Success", Type: FlashSuccess},
			{Message: "Error", Type: FlashError},
		}
		manager.Put(ctx, FlashMessagesKey, expectedMessages)

		messages := GetFlashMessages(c)

		assert.Equal(t, expectedMessages, messages)

		remainingMessages := manager.Get(ctx, FlashMessagesKey)
		assert.Nil(t, remainingMessages)
	})

	t.Run("no messages exist", func(t *testing.T) {
		c, _ := createTestContext()
		setupContextWithSessionManager(c)

		messages := GetFlashMessages(c)

		assert.Nil(t, messages)
	})

	t.Run("invalid message type", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		ctx := c.Request().Context()
		manager.Put(ctx, FlashMessagesKey, "invalid")

		messages := GetFlashMessages(c)

		assert.Nil(t, messages)
	})

	t.Run("without session manager", func(t *testing.T) {
		c, _ := createTestContext()

		messages := GetFlashMessages(c)

		assert.Nil(t, messages)
	})
}

func TestClearFlashMessages(t *testing.T) {
	t.Run("clear existing messages", func(t *testing.T) {
		c, _ := createTestContext()
		manager := setupContextWithSessionManager(c)

		ctx := c.Request().Context()
		messages := []FlashMessage{
			{Message: "Test", Type: FlashInfo},
		}
		manager.Put(ctx, FlashMessagesKey, messages)

		ClearFlashMessages(c)

		remainingMessages := manager.Get(ctx, FlashMessagesKey)
		assert.Nil(t, remainingMessages)
	})

	t.Run("clear when no messages exist", func(t *testing.T) {
		c, _ := createTestContext()
		setupContextWithSessionManager(c)

		ClearFlashMessages(c)
	})

	t.Run("without session manager", func(t *testing.T) {
		c, _ := createTestContext()

		ClearFlashMessages(c)
	})
}

func TestFlashTypes(t *testing.T) {
	tests := []struct {
		name      string
		flashType FlashType
		expected  string
	}{
		{"success", FlashSuccess, "success"},
		{"error", FlashError, "error"},
		{"warning", FlashWarning, "warning"},
		{"info", FlashInfo, "info"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, string(tt.flashType))
		})
	}
}

func TestFlashMessage(t *testing.T) {
	message := FlashMessage{
		Message: "Test message",
		Type:    FlashSuccess,
	}

	assert.Equal(t, "Test message", message.Message)
	assert.Equal(t, FlashSuccess, message.Type)
}
