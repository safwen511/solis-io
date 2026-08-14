package top

import (
	"bufio"
	"io"
)

type keyAction uint8

const (
	keyNone keyAction = iota
	keyQuit
	keyUp
	keyDown
	keySortName
	keySortPressure
	keySortWrite
	keySortOps
	keySortLatency
	keyRefresh
	keyHelp
	keyNextPanel
	keyPreviousPanel
	keyOpenPanel
	keyBack
	keyHomePanel
	keyDetailsPanel
	keyEventsPanel
	keyWorkflowsPanel
	keySaveDetail
)

func readKeyActions(src io.Reader) <-chan keyAction {
	actions := make(chan keyAction, 8)
	go func() {
		defer close(actions)
		reader := bufio.NewReader(src)
		for {
			value, err := reader.ReadByte()
			if err != nil {
				return
			}
			action := keyForByte(value)
			if value == 0x1b {
				action = readEscapeAction(reader)
			}
			if action != keyNone {
				actions <- action
			}
		}
	}()
	return actions
}

func keyForByte(value byte) keyAction {
	switch value {
	case 'q', 'Q', 0x03:
		return keyQuit
	case 'k', 'K':
		return keyUp
	case 'j', 'J':
		return keyDown
	case 'n', 'N':
		return keySortName
	case 'p', 'P':
		return keySortPressure
	case 'w', 'W':
		return keySortWrite
	case 'o', 'O':
		return keySortOps
	case 'l', 'L':
		return keySortLatency
	case 'r', 'R':
		return keyRefresh
	case '?', 'h', 'H':
		return keyHelp
	case '\t':
		return keyNextPanel
	case '\r', '\n':
		return keyOpenPanel
	case 'b', 'B':
		return keyBack
	case '1':
		return keyHomePanel
	case '2':
		return keyDetailsPanel
	case '3':
		return keyEventsPanel
	case '4':
		return keyWorkflowsPanel
	case 's', 'S':
		return keySaveDetail
	default:
		return keyNone
	}
}

func readEscapeAction(reader *bufio.Reader) keyAction {
	open, err := reader.ReadByte()
	if err != nil || open != '[' {
		return keyNone
	}
	direction, err := reader.ReadByte()
	if err != nil {
		return keyNone
	}
	switch direction {
	case 'A':
		return keyUp
	case 'B':
		return keyDown
	case 'C':
		return keyNextPanel
	case 'D':
		return keyPreviousPanel
	case 'Z':
		return keyPreviousPanel
	default:
		return keyNone
	}
}

func sortForKey(action keyAction) (string, bool) {
	switch action {
	case keySortName:
		return "name", true
	case keySortPressure:
		return "pressure", true
	case keySortWrite:
		return "write", true
	case keySortOps:
		return "ops", true
	case keySortLatency:
		return "latency", true
	default:
		return "", false
	}
}
