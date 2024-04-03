//
//  ViewController.swift
//  TunneledWebView
//
/*
 Licensed under Creative Commons Zero (CC0).
 https://creativecommons.org/publicdomain/zero/1.0/
 */


import UIKit
import WebKit

class ViewController: UIViewController {

    @IBOutlet var webView: WKWebView!

    override func viewDidLoad() {
        super.viewDidLoad()

        webView.isUserInteractionEnabled = true
        webView.scrollView.isScrollEnabled = true
    }

    override func didReceiveMemoryWarning() {
        super.didReceiveMemoryWarning()
        // Dispose of any resources that can be recreated.
    }

    func useProxyConfiguration(_ proxyConfig: ProxyConfiguration) {
        let websiteDataStore = WKWebsiteDataStore.default()
        websiteDataStore.proxyConfigurations = [proxyConfig]
        webView.configuration.websiteDataStore = websiteDataStore
    }

    func loadUrl(_ url: URL) {
        let request = URLRequest.init(url: url)
        self.webView.load(request)
    }
}
