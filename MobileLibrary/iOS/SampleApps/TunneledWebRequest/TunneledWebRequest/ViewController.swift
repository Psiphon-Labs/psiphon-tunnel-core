//
//  ViewController.swift
//  TunneledWebView
//
/*
 Licensed under Creative Commons Zero (CC0).
 https://creativecommons.org/publicdomain/zero/1.0/
 */


import UIKit

class ViewController: UIViewController {

    @IBOutlet var webView: UIWebView!

    var viewText: String = ""

    override func viewDidLoad() {
        super.viewDidLoad()

        webView.isUserInteractionEnabled = true
        webView.scrollView.isScrollEnabled = true
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

    func appendToView(_ text: String) {
        let escapedText = text.replacingOccurrences(of: "\r", with: "")

        self.viewText += "\n\n"
        self.viewText += escapedText

        let html = "<pre>" + self.viewText + "</pre>"

        self.webView.loadHTMLString(html, baseURL: nil)
    }

}
