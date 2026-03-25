# OSINT-Based Data Exposure Assessment Tool

This project was developed as part of my BSc (Hons) in Cyber Security & Digital Forensics.

## Overview
This application is designed to perform Open Source Intelligence (OSINT) analysis to identify potential data exposure risks using multiple external security APIs.

## Features
- Email breach detection (Have I Been Pwned API)
- IP reputation analysis (AbuseIPDB API)
- File/URL scanning (VirusTotal API)
- Password strength analysis
- Web scraping and data extraction
- User authentication system (Login/Signup)

## Technologies Used
- Python (Flask)
- HTML (Frontend Templates)
- SQLite (Database)
- REST APIs (HIBP, VirusTotal, AbuseIPDB)

## Project Structure
- analysis/ → Core analysis logic
- services/ → API integrations
- templates/ → Web interface
- app.py → Main application entry point

## Purpose
This tool demonstrates practical implementation of OSINT techniques and cybersecurity analysis for identifying publicly exposed data and potential threats.

## Disclaimer
This project is for educational purposes only.
