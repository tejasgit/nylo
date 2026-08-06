#!/bin/bash
set -e

# Install root dependencies (npm project)
npm install --no-audit --no-fund

# Install example server dependencies
cd examples && npm install --no-audit --no-fund
