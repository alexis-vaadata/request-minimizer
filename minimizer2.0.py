from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation, IParameter, IRequestInfo
from javax.swing import JMenuItem
from functools import partial
from threading import Thread
import json
import array
import traceback

IGNORED_INVARIANTS = set(['Report-To'])


Whitelist = ['Host', 'Content-Type', 'Content-Length']

class Miniminder(object):
    def __init__(self, callbacks, request):
        self._request = request[0]
        self._cb = callbacks
        self._helpers = callbacks.helpers
        self._httpServ = self._request.getHttpService()
        self._current_request = ""
        self._request_info = ""
        self._initial_body = []
        self._initial_headers = []
        self._initial_http_request = ""
        self._minimized_headers = []
        self._minimized_body = ""
        self._initial_invariants = set()
        self._initial_parameters = []
        self._request_to_send = ""
    
    def minimize(self, replace, event):
        Thread(target=self._minimize, args=(replace,)).start()

    def compare_requests(self, new_http_request):
        invariant = set(self._helpers.analyzeResponseVariations([self._initial_http_request, new_http_request]).getInvariantAttributes())
        return len(set(self._initial_invariants) - set(invariant)) == 0

    def minimize_headers(self):
        self._minimized_headers = []
        self._minimized_headers.append(self._initial_headers[0])
        for header in self._initial_headers[1:]:
            if any(header.startswith(s) for s in Whitelist):
                self._minimized_headers.append(header)
                continue
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
        self._request_info = self._helpers.analyzeRequest(self._request)
        self._initial_body = list(self._current_request[self._request_info.getBodyOffset():])
        self._initial_headers = list(self._request_info.getHeaders())
        self._initial_invariants = set(self._helpers.analyzeResponseVariations([self._initial_http_request, self._initial_http_request]).getInvariantAttributes())
        self._initial_invariants -= IGNORED_INVARIANTS 
        self._initial_parameters = list(self._request_info.getParameters())
        self._minimized_headers = list(self._initial_headers)[:]
        self._minimized_body = list(self._initial_body)[:] 
        
        return True

    def display(self, request):
        self._request.setRequest(request)
        return True
    
    def fix_content_type(self, headers, body):
        headers = headers.split('\r\n')
        for i in range(len(headers)):
            if headers[i].lower().startswith('content-length'):
                headers[i] = 'Content-Length: ' + str(len(body))
        return array.array('b', '\r\n'.join(headers) + body)
    
    def bf_search(self, body, check_func):
        if isinstance(body, dict):
            to_test = body.items()
            assemble = lambda l : dict(l)
        elif type(body) == list:
            to_test = zip(range(len(body)), body)
            assemble = lambda l: list(zip(*sorted(l))[1] if len(l) else [])
        tested = []
        while len(to_test):
            current = to_test.pop()
            if not check_func(assemble(to_test+tested)):
                tested.append(current)
        to_test = tested
        tested = []
        while len(to_test):
            key, value = to_test.pop()
            if isinstance(value,list) or isinstance(value, dict):
                def check_func_rec(body):
                    return check_func(assemble(to_test + tested + [(key, body)]))
                value = self.bf_search(value, check_func_rec)
            tested.append((key, value))
        return assemble(tested)
    
    def _fix_cookies(self, current_req):
        """ Workaround for a bug in extender,
        see https://support.portswigger.net/customer/portal/questions/17091600
        """
        cur_request_info = self._helpers.analyzeRequest(current_req)
        new_headers = []
        rebuild = False
        for header in self._initial_headers:
            if header.strip().lower() != 'cookie:':
                new_headers.append(header)
            else:
                rebuild = True
        if rebuild:
            return self._helpers.buildHttpMessage(new_headers, current_req[cur_request_info.getBodyOffset():])
        return current_req
    
    def minimize_body(self):
        try:
            self._minimized_body = []
            for param in self._initial_parameters:
                seen_xml = seen_json = False
                param_type = param.getType()
                if param_type in [IParameter.PARAM_URL, IParameter.PARAM_BODY, IParameter.PARAM_COOKIE]:
                    req = self._helpers.removeParameter(self._current_request, param)
                    resp = self._cb.makeHttpRequest(self._httpServ, req).getResponse()
                    if self.compare_requests(resp):
                        current_req = self._fix_cookies(req)
                    else:
                        if param_type == IParameter.PARAM_JSON:
                            seen_json = True
                        elif param_type == IParameter.PARAM_XML:
                            seen_xml = True
                        else:
                            print("Unsupported type:", param.getType())
                seen_json = (self._request_info.getContentType() == IRequestInfo.CONTENT_TYPE_JSON or seen_json)
                seen_xml = (self._request_info.getContentType() == IRequestInfo.CONTENT_TYPE_XML or seen_xml)
                if seen_json or seen_xml:
                    body_offset = self._request_info.getBodyOffset()
                    headers = self._request.getRequest()[:body_offset].tostring()
                    body = self._request.getRequest()[body_offset:].tostring()
                    if seen_json:
                        dumpmethod = partial(json.dumps, indent=4)
                        loadmethod = json.loads
                    elif seen_xml:
                        print('Sorry, unable to install xmltodict :)')
                        # dumpmethod = partial(xmltodict.unparse, pretty=True)
                        # loadmethod = xmltodict.parse
                    # The minimization routine for both xml and json is the same,
                    # the only difference is with load and dump functions    
                    def check(body):
                        if len(body) == 0 and not seen_json:
                            # XML with and no root node is invalid
                            return False
                        body = str(dumpmethod(body))
                        req = self.fix_content_type(headers, body)
                        resp = self._cb.makeHttpRequest(self._httpServ, req).getResponse()
                        if self.compare_requests(resp):
                            return True
                        else:
                            return False
                    body = loadmethod(body)
                    body = self.bf_search(body, check)
                    self._minimized_body = str(dumpmethod(body))
                    return True
                else:
                    current_req = '\r\n'.join(self._minimized_headers)
                    return current_req
        except:
            print(traceback.format_exc())
        return True

    def _minimize(self, choice):
        self.init_requests()
        if choice == 0:
                self.minimize_headers()
                self._request_to_send = self._helpers.buildHttpMessage(self._minimized_headers, self._minimized_body)
        elif choice == 1:
                self.minimize_body()
                arr = array.array('b', str(self._minimized_body))
                self._request_to_send = self._helpers.buildHttpMessage(self._minimized_headers, arr)
        elif choice == 2:
                self.minimize_headers()
                self.minimize_body()
                arr = array.array('b', str(self._minimized_body))
                self._request_to_send = self._helpers.buildHttpMessage(self._minimized_headers, arr)
        else:
            print("Error :  Bad choice")
        self.display(self._request_to_send)
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
                    "Minimize Headers",
                    actionPerformed=partial(
                        Miniminder(self._callbacks, invocation.getSelectedMessages()).minimize, 0
                    )
                ),
                JMenuItem(
                    "Minimize Body",
                    actionPerformed=partial(
                        Miniminder(self._callbacks, invocation.getSelectedMessages()).minimize, 1
                    )
                ),JMenuItem(
                    "Minimize All",
                    actionPerformed=partial(
                        Miniminder(self._callbacks, invocation.getSelectedMessages()).minimize, 2
                    )
                ),
            ]
