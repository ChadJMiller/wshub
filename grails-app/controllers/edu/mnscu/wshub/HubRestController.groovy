package edu.mnscu.wshub

import grails.converters.JSON

class HubRestController {

    def index() {
        def map = [msg: "test message"]
        render map as JSON
    }
}
