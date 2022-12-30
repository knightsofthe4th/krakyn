@echo off

SET CURL=curl https://sum.golang.org/lookup/github.com/knightsofthe4th/krakyn
SET VERS=%1
SET CMD=%CURL%@%VERS%

%CMD%