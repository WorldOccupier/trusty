package hallucination

import (
	"testing"

	"github.com/WorldOccupier/trusty/internal/types"
)

func TestNewDetector(t *testing.T) {
	d := NewDetector()
	if d == nil {
		t.Fatal("NewDetector() returned nil")
	}
	if d.registry == nil {
		t.Fatal("Detector has nil registry")
	}
}

func TestDetect_EmptyContent(t *testing.T) {
	d := NewDetector()
	findings := d.Detect("", "", "")
	if findings != nil {
		t.Fatalf("expected nil, got %v", findings)
	}
}

func TestDetect_UnknownLanguage(t *testing.T) {
	d := NewDetector()
	findings := d.Detect("file.xyz", "some random content", "")
	if findings != nil {
		t.Fatalf("expected nil for unknown language, got %v", findings)
	}
}

func TestDetect_Go_StdlibOnly(t *testing.T) {
	d := NewDetector()
	content := `package main

import (
	"fmt"
	"os"
	"strings"
)
`
	findings := d.Detect("main.go", content, "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for stdlib imports, got %d: %v", len(findings), findings)
	}
}

func TestDetect_Go_WellKnownOnly(t *testing.T) {
	d := NewDetector()
	content := `package main

import (
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
)
`
	findings := d.Detect("main.go", content, "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for well-known imports, got %d: %v", len(findings), findings)
	}
}

func TestDetect_Go_LocalModule(t *testing.T) {
	d := NewDetector()
	content := `module github.com/WorldOccupier/trusty

package main

import (
	"github.com/WorldOccupier/trusty/internal/types"
)
`
	findings := d.Detect("main.go", content, "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for local module imports, got %d: %v", len(findings), findings)
	}
}

func TestDetect_Go_NoImports(t *testing.T) {
	d := NewDetector()
	content := `package main

func main() {}
`
	findings := d.Detect("main.go", content, "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for no imports, got %d: %v", len(findings), findings)
	}
}

func TestDetect_Go_InvalidSyntax(t *testing.T) {
	d := NewDetector()
	content := `package main
import (
	"fmt"
*** invalid ***
`
	findings := d.Detect("main.go", content, "")
	if findings != nil {
		t.Fatalf("expected nil on parse error, got %v", findings)
	}
}

func TestDetect_Python_WellKnown(t *testing.T) {
	d := NewDetector()
	content := `import os
import sys
from collections import defaultdict
`
	findings := d.Detect("script.py", content, "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for well-known python modules, got %d: %v", len(findings), findings)
	}
}

func TestDetect_Python_Unknown(t *testing.T) {
	d := NewDetector()
	content := `import flibbertigibbet
from nonexistent_lib import something
`
	findings := d.Detect("script.py", content, "")
	if len(findings) == 0 {
		t.Fatal("expected findings for unknown python modules")
	}
	for _, f := range findings {
		if f.Category != "hallucination" {
			t.Errorf("expected category 'hallucination', got %q", f.Category)
		}
		if f.Rule != "hallucinated-import" {
			t.Errorf("expected rule 'hallucinated-import', got %q", f.Rule)
		}
		if f.Severity != types.SeverityError {
			t.Errorf("expected severity Error, got %v", f.Severity)
		}
	}
}

func TestDetect_Python_RelativeImport(t *testing.T) {
	d := NewDetector()
	content := `from . import sibling
from ..parent import thing
`
	findings := d.Detect("script.py", content, "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for relative imports, got %d: %v", len(findings), findings)
	}
}

func TestDetect_JavaScript_WellKnown(t *testing.T) {
	d := NewDetector()
	content := `import React from 'react'
import express from 'express'
const _ = require('lodash')
`
	findings := d.Detect("app.js", content, "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for well-known js modules, got %d: %v", len(findings), findings)
	}
}

func TestDetect_JavaScript_Unknown(t *testing.T) {
	d := NewDetector()
	content := `import superobscurepkg from 'superobscurepkg'
`
	findings := d.Detect("app.js", content, "")
	if len(findings) == 0 {
		t.Fatal("expected findings for unknown js module")
	}
}

func TestDetect_JavaScript_RelativeImport(t *testing.T) {
	d := NewDetector()
	content := `import Component from './Component'
import utils from '../../utils'
`
	findings := d.Detect("app.js", content, "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for relative imports, got %d: %v", len(findings), findings)
	}
}

func TestDetect_JavaScript_AbsoluteImport(t *testing.T) {
	d := NewDetector()
	content := `import config from '/etc/config'
`
	findings := d.Detect("app.js", content, "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for absolute imports, got %d: %v", len(findings), findings)
	}
}

func TestDetect_TypeScript(t *testing.T) {
	d := NewDetector()
	content := `const fs = require('fs-extra')
`
	findings := d.Detect("app.ts", content, "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for well-known js modules from ts, got %d: %v", len(findings), findings)
	}
}

func TestDetect_Python_ImportWithAlias(t *testing.T) {
	d := NewDetector()
	content := `import numpy as np
import pandas as pd
`
	findings := d.Detect("script.py", content, "")
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for well-known aliased imports, got %d: %v", len(findings), findings)
	}
}

func TestDetect_Go_UnknownExternal(t *testing.T) {
	d := NewDetector()
	content := `package main

import "github.com/WorldOccupier/made-up-module-that-does-not-exist"
`
	findings := d.Detect("main.go", content, "")
	for _, f := range findings {
		if f.Rule == "hallucinated-import" {
			return
		}
	}
}
