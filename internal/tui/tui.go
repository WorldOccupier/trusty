package tui

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/WorldOccupier/trusty/internal/report"
	"github.com/WorldOccupier/trusty/internal/scanner"
	"github.com/WorldOccupier/trusty/internal/types"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#00FF88")).
			Padding(0, 1)

	fileStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Padding(0, 1)

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#000000")).
			Background(lipgloss.Color("#00FF88")).
			Padding(0, 1)

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF4444"))

	warnStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFAA00"))

	infoStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888"))

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#666666")).
			Padding(0, 1)
)

type model struct {
	files      []types.FileResult
	cursor     int
	selected   int
	detailView bool
	width      int
	height     int
	ready      bool
}

func Run(s *scanner.Scanner, opts types.DiffOptions) error {
	result, err := s.Scan(nil, opts)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	if result == nil || len(result.Files) == 0 {
		fmt.Println("No findings to display.")
		return nil
	}

	p := tea.NewProgram(initialModel(result.Files), tea.WithAltScreen())
	_, err = p.Run()
	return err
}

func RunWithResult(scanResult types.ScanResult) error {
	if len(scanResult.Files) == 0 {
		fmt.Println("No findings to display.")
		return nil
	}

	p := tea.NewProgram(initialModel(scanResult.Files), tea.WithAltScreen())
	_, err := p.Run()
	return err
}

func initialModel(files []types.FileResult) model {
	return model{
		files:    files,
		cursor:   0,
		selected: -1,
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.ready = true
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c", "esc":
			if m.detailView {
				m.detailView = false
				return m, nil
			}
			return m, tea.Quit
		case "up", "k":
			if m.detailView {
				return m, nil
			}
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.detailView {
				return m, nil
			}
			if m.cursor < len(m.files)-1 {
				m.cursor++
			}
		case "enter", " ":
			if m.detailView {
				return m, nil
			}
			if m.cursor >= 0 && m.cursor < len(m.files) {
				if len(m.files[m.cursor].Findings) > 0 {
					m.selected = m.cursor
					m.detailView = true
				}
			}
		}
	}
	return m, nil
}

func (m model) View() string {
	if !m.ready {
		return "Loading..."
	}

	var b strings.Builder

	if m.detailView && m.selected >= 0 {
		m.renderDetail(&b)
		return b.String()
	}

	titleStyle.Width(m.width)
	b.WriteString(titleStyle.Render("Trusty Scan Results"))
	b.WriteString("\n\n")

	for i, file := range m.files {
		line := fmt.Sprintf("%s (%d findings, score: %d)",
			file.Path, len(file.Findings), file.Score)

		if i == m.cursor {
			b.WriteString(selectedStyle.Render("> " + line))
		} else {
			b.WriteString(fileStyle.Render("  " + line))
		}
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(helpStyle.Render("↑/↓ navigate • enter view details • q quit"))
	return b.String()
}

func (m *model) renderDetail(b *strings.Builder) {
	file := m.files[m.selected]
	b.WriteString(titleStyle.Render(fmt.Sprintf("Findings: %s", file.Path)))
	b.WriteString("\n\n")

	for _, f := range file.Findings {
		var style lipgloss.Style
		switch f.Severity {
		case types.SeverityError:
			style = errorStyle
		case types.SeverityWarning:
			style = warnStyle
		default:
			style = infoStyle
		}

		sevStr := "INFO"
		switch f.Severity {
		case types.SeverityError:
			sevStr = "ERROR"
		case types.SeverityWarning:
			sevStr = "WARN"
		}

		b.WriteString(style.Render(fmt.Sprintf("[%s] %s", sevStr, f.Rule)))
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s\n", f.Message))
		if f.Line > 0 {
			b.WriteString(fmt.Sprintf("  Line: %d\n", f.Line))
		}
		if f.Suggestion != "" {
			b.WriteString(fmt.Sprintf("  Suggestion: %s\n", f.Suggestion))
		}
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(helpStyle.Render("esc back • q quit"))
}

func RunFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading scan result: %w", err)
	}

	result := report.ParseResult(data)
	if result == nil {
		return fmt.Errorf("parsing scan result: %w", err)
	}

	return RunWithResult(*result)
}
