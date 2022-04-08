from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation, IParameter
from javax.swing import JMenuItem
from functools import partial
from threading import Thread

IGNORED_INVARIANTS = set(['last_modified_header'])

class Miniminder(object):
    def __init__(self, callbacks, request):
        self._request = request[0]
        self._cb = callbacks
        self._helpers = callbacks.helpers
        self._httpServ = self._request.getHttpService()
        self._current_request = ""
        self._initial_body = []
        self._initial_headers = []
        self._initial_http_request = ""
        self._minimized_headers = []
        self._minimized_body = []
        self._initial_invariants = set()
        
        self._initial_parameters = []
    
    def minimize(self, replace, event):
        Thread(target=self._minimize, args=(replace,)).start()

    def compare_requests(self, new_http_request):
        invariants = set(self._helpers.analyzeResponseVariations([self._initial_http_request, new_http_request]).getInvariantAttributes())
        return len(set(self._initial_invariants) - set(invariants)) == 0

    def minimize_headers(self):
        for header in self._initial_headers:
            copy_headers = list(self._initial_headers)[:]
            copy_headers.remove(header)
            request = self._helpers.buildHttpMessage(copy_headers, self._initial_body)
            new_http_request = self._cb.makeHttpRequest(self._httpServ, request).getResponse()
            if self.compare_requests(new_http_request):
                continue
            else:
                self._minimized_headers.append(header)
        return True

    def init_requests(self):
        self._current_request = self._request.getRequest()
        self._initial_http_request = self._cb.makeHttpRequest(self._httpServ, self._current_request).getResponse()
        request_info = self._helpers.analyzeRequest(self._request)
        self._initial_body = list(self._initial_http_request[request_info.getBodyOffset():])
        self._initial_headers = list(request_info.getHeaders())
        self._initial_invariants = set(self._helpers.analyzeResponseVariations([self._initial_http_request, self._initial_http_request]).getInvariantAttributes())
        self._initial_invariants -= IGNORED_INVARIANTS
        
        # Params : Body + Cookies + JSON + Multipart + URL + XML + XML_ATTR 
        # Params Types : 0=URL; 1=BODY; 2=COOKIE; 6=JSON; IParameter.PARAM_URL, IParameter.PARAM_BODY, IParameter.PARAM_COOKIE
        self._initial_parameters = list(request_info.getParameters())
        # param_type = param.getType()
        #         if param_type in [IParameter.PARAM_URL, IParameter.PARAM_BODY, IParameter.PARAM_COOKIE]:
        # print("Initial Parameters : ")
        # for x in self._initial_parameters:
        #     print(x.getName(), x.getType())
        return True

    def display(self, new_tab, request):
        if (new_tab == True):
            self._cb.sendToRepeater(
                self._httpServ.getHost(),
                self._httpServ.getPort(),
                self._httpServ.getProtocol() == 'https',
                request,
                "Minimizer 2.0"
            )
        else:
            self._request.setRequest(request)
        return True
    
    def minimize_body(self):
        for param in self._initial_parameters:
            param_type = param.getType()
            if param_type in [IParameter.PARAM_URL, IParameter.PARAM_BODY, IParameter.PARAM_COOKIE, IParameter.PARAM_JSON]:
                print("Trying : ", param_type, param.getName(), param.getValue())
                request = self._helpers.removeParameter(self._current_request, param)
                http_response = self._cb.makeHttpRequest(self._httpServ, request).getResponse()
                if self.compare_requests(http_response):
                    print("Deleted : ", param.getName())
                else:
                    print("Keep : ", param.getName())
                    self._minimized_body.append(param.getName())
                    # current_req = self._fix_cookies(request, self.)
        return True

    def _minimize(self, new_tab):
        self.init_requests()
        self.minimize_headers()
        print("Minimized Headers : ", self._minimized_headers)

        self.minimize_body()
        print("Minimized Body : ", self._minimized_body)
        request = '\r\n'.join(self._minimized_headers)
        self.display(new_tab, request)
        return True


class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("Minimizer 2.0")
        callbacks.registerContextMenuFactory(self)
        self._callbacks = callbacks

    def createMenuItems(self, invocation):
        if invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            return [
                JMenuItem(
                    "Current Tab",
                    actionPerformed=partial(
                        Miniminder(self._callbacks, invocation.getSelectedMessages()).minimize, False
                    )
                ),
                JMenuItem(
                    "New Tab",
                    actionPerformed=partial(
                        Miniminder(self._callbacks, invocation.getSelectedMessages()).minimize, True
                    )
                ),
            ]
