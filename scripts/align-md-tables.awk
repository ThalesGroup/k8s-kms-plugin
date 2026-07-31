#!/usr/bin/awk -f
#
# Align the columns of every GitHub-flavored Markdown table read on stdin and
# write the result to stdout. Non-table lines pass through untouched.
#
# Go's text/template cannot pad cells to a common width (it has no lookahead
# over the whole row set), so `make notices` renders a ragged table and pipes it
# through here.
#
# Usage: awk -f scripts/align-md-tables.awk < in.md > out.md

BEGIN {
	# Dashes to keep in a separator cell at minimum. GFM accepts one, but three
	# is the near-universal convention among Markdown formatters.
	MIN_DASHES = 3
}

# Strip leading/trailing whitespace.
function trim(s) {
	sub(/^[ \t]+/, "", s)
	sub(/[ \t]+$/, "", s)
	return s
}

# Split a table row into the cells[] array, dropping the empty fields produced
# by the leading and trailing pipes. Returns the cell count.
function cells_of(line, cells,   n, i, parts, count) {
	line = trim(line)
	sub(/^\|/, "", line)
	sub(/\|$/, "", line)
	n = split(line, parts, /\|/)
	count = 0
	for (i = 1; i <= n; i++)
		cells[++count] = trim(parts[i])
	return count
}

# A separator row is one whose cells are all of the form ---, :---, ---: or :-:.
function is_separator(line,   cells, n, i) {
	n = cells_of(line, cells)
	if (n == 0)
		return 0
	for (i = 1; i <= n; i++)
		if (cells[i] !~ /^:?-+:?$/)
			return 0
	return 1
}

function pad(s, w,   out) {
	out = s
	while (length(out) < w)
		out = out " "
	return out
}

function repeat(c, n,   out) {
	out = ""
	while (n-- > 0)
		out = out c
	return out
}

# Shortest a separator cell can be: its alignment colons plus MIN_DASHES dashes.
# A column narrower than this has to be widened, or the separator row would
# overflow and knock the pipes out of line.
function separator_min(spec) {
	return (spec ~ /^:/) + (spec ~ /:$/) + MIN_DASHES
}

# Rebuild a separator cell at the target width, preserving its alignment colons.
function separator_cell(spec, w,   left, right, dashes) {
	left = (spec ~ /^:/)
	right = (spec ~ /:$/)
	dashes = w - left - right
	if (dashes < MIN_DASHES)
		dashes = MIN_DASHES
	return (left ? ":" : "") repeat("-", dashes) (right ? ":" : "")
}

# Emit the buffered table, padding every column to its widest cell.
function flush_table(   r, c, cells, n, line, maxcols) {
	if (nrows == 0)
		return
	maxcols = 0
	for (r = 1; r <= nrows; r++) {
		line = "|"
		n = split(row[r], cells, SUBSEP)
		if (n > maxcols)
			maxcols = n
		for (c = 1; c <= n; c++) {
			if (sep[r])
				line = line " " separator_cell(cells[c], width[c]) " |"
			else
				line = line " " pad(cells[c], width[c]) " |"
		}
		print line
	}
	nrows = 0
	# Reset per-column widths element by element: `delete width` as a whole-array
	# statement is a common extension, not POSIX, and this runs under whatever
	# awk the host provides (gawk, mawk, busybox).
	for (c = 1; c <= maxcols; c++)
		width[c] = 0
}

/^[ \t]*\|/ {
	n = cells_of($0, cells)
	nrows++
	sep[nrows] = is_separator($0)
	buf = ""
	for (i = 1; i <= n; i++) {
		buf = buf (i > 1 ? SUBSEP : "") cells[i]
		# A separator cell stretches to fit the column rather than dictating its
		# width, but it still imposes a floor (see separator_min).
		w = sep[nrows] ? separator_min(cells[i]) : length(cells[i])
		if (w > width[i])
			width[i] = w
	}
	row[nrows] = buf
	next
}

{
	flush_table()
	print
}

END {
	flush_table()
}
