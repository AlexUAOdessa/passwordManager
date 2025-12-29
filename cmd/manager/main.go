package main

import (
	"passwordManager/internal/ui"

	"fyne.io/fyne/v2/app"
)

func main() {
	myApp := app.New()
	window := myApp.NewWindow("Go Safe Manager")
	
	ui.StartUI(window)
	
	window.ShowAndRun()
}