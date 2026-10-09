package ast

import (
	"testing"

	"bonjoski/argus/internal/model"
)

func TestStdlib(t *testing.T) {
	// Python stdlib tests
	if !IsPythonStdlib("sys") {
		t.Errorf("expected sys to be Python stdlib")
	}
	if !IsPythonStdlib("os.path") {
		t.Errorf("expected os.path to be Python stdlib")
	}
	if !IsPythonStdlib("pathlib") {
		t.Errorf("expected pathlib to be Python stdlib")
	}
	if IsPythonStdlib("requests") {
		t.Errorf("requests must not be Python stdlib")
	}
	if IsPythonStdlib("requests_jwt_validator") {
		t.Errorf("requests_jwt_validator must not be Python stdlib")
	}

	// Node.js stdlib tests
	if !IsNodeStdlib("fs") {
		t.Errorf("expected fs to be Node stdlib")
	}
	if !IsNodeStdlib("node:crypto") {
		t.Errorf("expected node:crypto to be Node stdlib")
	}
	if !IsNodeStdlib("path") {
		t.Errorf("expected path to be Node stdlib")
	}
	if IsNodeStdlib("express") {
		t.Errorf("express must not be Node stdlib")
	}
	if IsNodeStdlib("express-auth-phantom") {
		t.Errorf("express-auth-phantom must not be Node stdlib")
	}

	// Go stdlib tests
	if !IsGoStdlib("fmt") {
		t.Errorf("expected fmt to be Go stdlib")
	}
	if !IsGoStdlib("net/http") {
		t.Errorf("expected net/http to be Go stdlib")
	}
	if !IsGoStdlib("crypto/sha256") {
		t.Errorf("expected crypto/sha256 to be Go stdlib")
	}
	if IsGoStdlib("github.com/gin-gonic/gin") {
		t.Errorf("github.com/gin-gonic/gin must not be Go stdlib")
	}
	if IsGoStdlib("github.com/phantom/fake-pkg") {
		t.Errorf("github.com/phantom/fake-pkg must not be Go stdlib")
	}
}

func TestNormalizer(t *testing.T) {
	// Python normalizations
	casesPy := map[string]string{
		"sklearn":                "scikit-learn",
		"sklearn.ensemble":       "scikit-learn",
		"PIL":                    "Pillow",
		"PIL.Image":              "Pillow",
		"yaml":                   "PyYAML",
		"bs4":                    "beautifulsoup4",
		"cv2":                    "opencv-python",
		"google.protobuf":        "protobuf",
		"dotenv":                 "python-dotenv",
		"dateutil":               "python-dateutil",
		"jwt":                    "PyJWT",
		"requests":               "requests",
		"requests_jwt_validator": "requests_jwt_validator",
		"os":                     "", // stdlib -> empty
		"sys":                    "", // stdlib -> empty
	}
	for in, expected := range casesPy {
		got := NormalizeImport(model.EcosystemPyPI, in)
		if got != expected {
			t.Errorf("Python NormalizeImport(%q) = %q; want %q", in, got, expected)
		}
	}

	// JS/TS normalizations
	casesJS := map[string]string{
		"express":               "express",
		"lodash/get":            "lodash",
		"@angular/core":         "@angular/core",
		"@angular/core/testing": "@angular/core",
		"./local/module":        "",
		"../parent":             "",
		"node:fs":               "",
		"fs":                    "",
		"express-auth-phantom":  "express-auth-phantom",
	}
	for in, expected := range casesJS {
		got := NormalizeImport(model.EcosystemNPM, in)
		if got != expected {
			t.Errorf("JS NormalizeImport(%q) = %q; want %q", in, got, expected)
		}
	}

	// Go normalizations
	casesGo := map[string]string{
		"fmt":                              "",
		"net/http":                         "",
		"github.com/gin-gonic/gin/binding": "github.com/gin-gonic/gin",
		"github.com/phantom/fake-pkg":      "github.com/phantom/fake-pkg",
		"golang.org/x/crypto/ssh":          "golang.org/x/crypto",
		"gopkg.in/yaml.v2":                 "gopkg.in/yaml.v2",
		"go.uber.org/zap":                  "go.uber.org/zap",
	}
	for in, expected := range casesGo {
		got := NormalizeImport(model.EcosystemGo, in)
		if got != expected {
			t.Errorf("Go NormalizeImport(%q) = %q; want %q", in, got, expected)
		}
	}
}

func TestPythonImportParser(t *testing.T) {
	code := `
import os
import sys
import requests
import sklearn.ensemble
from PIL import Image
from requests_jwt_validator import (
    TokenValidator,
    AuthConfig,
)
from .local_module import my_func
from ..parent_mod import parent_func
# import fake_in_comment
"""
import fake_in_docstring
"""
import bs4, yaml as pyyaml
`
	candidates, err := ParsePythonImports("test.py", code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedPkgs := map[string]bool{
		"requests":               true,
		"scikit-learn":           true,
		"Pillow":                 true,
		"requests_jwt_validator": true,
		"beautifulsoup4":         true,
		"PyYAML":                 true,
	}

	if len(candidates) != len(expectedPkgs) {
		t.Fatalf("expected %d candidates, got %d: %+v", len(expectedPkgs), len(candidates), candidates)
	}

	for _, c := range candidates {
		if !expectedPkgs[c.PackageName] {
			t.Errorf("unexpected package extracted: %s", c.PackageName)
		}
		if c.Ecosystem != model.EcosystemPyPI {
			t.Errorf("expected PyPI ecosystem, got %s", c.Ecosystem)
		}
	}
}

func TestJavaScriptImportParser(t *testing.T) {
	code := `
import express from 'express';
import { get } from 'lodash/subpath';
import * as core from "@angular/core/testing";
import "./local-component";
import fs from "fs";
import crypto from "node:crypto";
// import comment_pkg from 'comment_pkg';
/*
import block_pkg from 'block_pkg';
*/
const phantom = require("express-auth-phantom");
const dynamic = await import('dynamic-pkg/entry');
export { helper } from 'export-pkg';
`
	candidates, err := ParseJavaScriptImports("test.ts", code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedPkgs := map[string]bool{
		"express":              true,
		"lodash":               true,
		"@angular/core":        true,
		"express-auth-phantom": true,
		"dynamic-pkg":          true,
		"export-pkg":           true,
	}

	if len(candidates) != len(expectedPkgs) {
		t.Fatalf("expected %d candidates, got %d: %+v", len(expectedPkgs), len(candidates), candidates)
	}

	for _, c := range candidates {
		if !expectedPkgs[c.PackageName] {
			t.Errorf("unexpected JS package extracted: %s", c.PackageName)
		}
		if c.Ecosystem != model.EcosystemNPM {
			t.Errorf("expected NPM ecosystem, got %s", c.Ecosystem)
		}
	}
}

func TestGoImportParser(t *testing.T) {
	code := `package main

import (
	"fmt"
	"net/http"
	"github.com/gin-gonic/gin/binding"
	fake "github.com/phantom/fake-pkg/sub"
	"golang.org/x/crypto/ssh"
)
`
	candidates, err := ParseGoImports("main.go", code)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedPkgs := map[string]bool{
		"github.com/gin-gonic/gin":    true,
		"github.com/phantom/fake-pkg": true,
		"golang.org/x/crypto":         true,
	}

	if len(candidates) != len(expectedPkgs) {
		t.Fatalf("expected %d candidates, got %d: %+v", len(expectedPkgs), len(candidates), candidates)
	}

	for _, c := range candidates {
		if !expectedPkgs[c.PackageName] {
			t.Errorf("unexpected Go package extracted: %s", c.PackageName)
		}
		if c.Ecosystem != model.EcosystemGo {
			t.Errorf("expected Go ecosystem, got %s", c.Ecosystem)
		}
	}
}

func TestTier2TreeSitterEngine(t *testing.T) {
	engine := NewTier2TreeSitterEngine()
	if engine.Tier() != 2 {
		t.Fatalf("expected engine tier 2, got %d", engine.Tier())
	}

	// 1. Rust CST parsing
	rustCode := `
use std::collections::HashMap;
use serde::Deserialize;
use tokio::sync::Mutex;
extern crate log;
`
	rustCands, err := engine.ExtractImports("src/main.rs", rustCode)
	if err != nil {
		t.Fatalf("Rust extraction error: %v", err)
	}
	rustPkgs := make(map[string]bool)
	for _, c := range rustCands {
		rustPkgs[c.PackageName] = true
	}
	if !rustPkgs["serde"] || !rustPkgs["tokio"] || !rustPkgs["log"] {
		t.Errorf("expected serde, tokio, log in Rust candidates, got: %+v", rustPkgs)
	}
	if rustPkgs["std"] {
		t.Errorf("std must not be in Rust candidates")
	}

	// 2. Ruby CST parsing
	rubyCode := `
require 'json'
require 'faraday'
gem 'rails'
`
	rubyCands, err := engine.ExtractImports("app.rb", rubyCode)
	if err != nil {
		t.Fatalf("Ruby extraction error: %v", err)
	}
	rubyPkgs := make(map[string]bool)
	for _, c := range rubyCands {
		rubyPkgs[c.PackageName] = true
	}
	if !rubyPkgs["faraday"] || !rubyPkgs["rails"] {
		t.Errorf("expected faraday, rails in Ruby candidates, got: %+v", rubyPkgs)
	}
	if rubyPkgs["json"] {
		t.Errorf("json must not be in Ruby candidates")
	}

	// 3. S-expression query matching
	query := `(import_statement (name) @pkg)`
	matches := engine.Query(query, "import express from 'express';\nconst x = 1;\nrequire('lodash');\n")
	if len(matches) < 2 {
		t.Errorf("expected at least 2 query matches, got: %+v", matches)
	}
}
