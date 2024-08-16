package utils

import (
	"fmt"
	"strings"
)

type Table struct {
	Headers []string
	Rows    [][]string
}

func (t *Table) Print() {
	if len(t.Rows) == 0 {
		return
	}

	numCols := len(t.Rows[0])
	colWidths := make([]int, numCols)

	if len(t.Headers) > 0 {
		for i, h := range t.Headers {
			colWidths[i] = len(h)
		}
	}

	for _, row := range t.Rows {
		for i, cell := range row {
			if len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}

	makeBorder := func(left, mid, right, fill string) string {
		var b strings.Builder
		b.WriteString(left)
		for i, w := range colWidths {
			b.WriteString(strings.Repeat(fill, w+2))
			if i < len(colWidths)-1 {
				b.WriteString(mid)
			}
		}
		b.WriteString(right)
		return b.String()
	}

	topBorder := makeBorder("┌", "┬", "┐", "─")
	midBorder := makeBorder("├", "┼", "┤", "─")
	botBorder := makeBorder("└", "┴", "┘", "─")

	printRow := func(row []string) {
		fmt.Print("│")
		for i, cell := range row {
			fmt.Printf(" %-*s │", colWidths[i], cell)
		}
		fmt.Println()
	}

	fmt.Println(topBorder)
	if len(t.Headers) > 0 {
		printRow(t.Headers)
		fmt.Println(midBorder)
	}
	for _, row := range t.Rows {
		printRow(row)
	}
	fmt.Println(botBorder)
}
