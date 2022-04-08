from burp import IBurpExtender, IContextMenuFactory, IContextMenuInvocation
from burp import IParameter, IRequestInfo
from java.net import URL, URLClassLoader
from java.lang import Thread as JavaThread
from javax.swing import JMenuItem
import array

# import xmltodict

from threading import Thread
from functools import partial
import json
import time
import copy
import sys
import traceback

IGNORED_INVARIANTS = set(['last_modified_header'])

class Minimizer(object):
    def __init__(self, callbacks, request):
        self._cb = callbacks
        self._helpers = callbacks.helpers
        self._request = request[0]
        self._httpServ = self._request.getHttpService()
    
    def _fix_classloader_problems(self):
        # Get path to jython jar
        jython_jar = None
        for path in sys.path:
            if '.jar' in path and 'jython' in path.lower():
                jython_jar = path[:path.index('.jar')+4]
        if jython_jar is None:
            raise Exception("Could not locate jython jar in path!")
        classloader = URLClassLoader([URL("file://" + jython_jar)], JavaThread.currentThread().getContextClassLoader())
        JavaThread.currentThread().setContextClassLoader(classloader);

    def compare(self, etalon, response, etalon_invariant):
        invariant = set(self._helpers.analyzeResponseVariations([etalon, response]).getInvariantAttributes())
        # print("Invariant", invariant)
        # print("diff", set(etalon_invariant) - set(invariant))
        return len(set(etalon_invariant) - set(invariant)) == 0

    def minimize(self, replace, event):
        Thread(target=self._minimize, args=(replace,)).start()

    def _fix_cookies(self, current_req, headers_minimized):
        """ Workaround for a bug in extender,
        see https://support.portswigger.net/customer/portal/questions/17091600
        """
        cur_request_info = self._helpers.analyzeRequest(current_req)
        new_headers = []
        rebuild = False
        for header in headers_minimized:
            if header.strip().lower() != 'cookie:':
                new_headers.append(header)
            else:
                rebuild = True
        if rebuild:
            return self._helpers.buildHttpMessage(new_headers, current_req[cur_request_info.getBodyOffset():])
        return current_req

    def _fix_headers(self, request_info, etalon, invariant, current_req):
        headers_list = request_info.getHeaders()
        new_header_list = []
        message_body = etalon[request_info.getBodyOffset():]
        for header in headers_list:
            checked_list = list(headers_list)[:]
            checked_list.remove(header)
            new_req = self._helpers.buildHttpMessage(checked_list, message_body)
            resp = self._cb.makeHttpRequest(self._httpServ, new_req).getResponse()
            if self.compare(etalon, resp, invariant):
                continue
            else:
                new_header_list.append(header)
        return new_header_list



    def _minimize(self, replace):
        try:
            self._fix_classloader_problems()
            seen_json = seen_xml = False
            request_info = self._helpers.analyzeRequest(self._request)
            current_req = self._request.getRequest()
            etalon = self._cb.makeHttpRequest(self._httpServ, current_req).getResponse()
            invariants = set(self._helpers.analyzeResponseVariations([etalon, etalon]).getInvariantAttributes())
            invariants -= IGNORED_INVARIANTS
            headers_minimized = self._fix_headers(request_info, etalon, invariants, current_req)
            for param in request_info.getParameters():
                param_type = param.getType()
                if param_type in [IParameter.PARAM_URL, IParameter.PARAM_BODY, IParameter.PARAM_COOKIE]:
                    print("Trying", param_type, param.getName(), param.getValue())
                    req = self._helpers.removeParameter(current_req, param)
                    resp = self._cb.makeHttpRequest(self._httpServ, req).getResponse()
                    if self.compare(etalon, resp, invariants):
                        current_req = self._fix_cookies(req, headers_minimized)
                else:
                    if param_type == IParameter.PARAM_JSON:
                        seen_json = True
                    elif param_type == IParameter.PARAM_XML:
                        seen_xml = True
                    else:
                        print("Unsupported type:", param.getType())
            print("Headers : ", headers_minimized)
            seen_json = (request_info.getContentType() == IRequestInfo.CONTENT_TYPE_JSON or seen_json)
            seen_xml = (request_info.getContentType() == IRequestInfo.CONTENT_TYPE_XML or seen_xml)
            if seen_json or seen_xml:
                print("JSON Detected :)")
                body_offset = request_info.getBodyOffset()
                headers = '\r\n'.join(headers_minimized)
                body = self._request.getRequest()[body_offset:].tostring()
                if seen_json:
                    print('Minimizing json...')
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
                    req = fix_content_length(headers_minimized, body)
                    resp = self._cb.makeHttpRequest(self._httpServ, req).getResponse()
                    if self.compare(etalon, resp, invariants):
                        print("Not changed: " + body)
                        return True
                    else:
                        print("Changed: " + body)
                        return False
                body = loadmethod(body)
                body = bf_search(body, check)
                current_req = fix_content_length(headers, str(dumpmethod(body)))
            else:
                current_req = '\r\n'.join(headers_minimized)
            if replace:
                self._request.setRequest(current_req)
            else:
                self._cb.sendToRepeater(
                        self._httpServ.getHost(),
                        self._httpServ.getPort(),
                        self._httpServ.getProtocol() == 'https',
                        current_req,
                       headers_minimized[0]
                )
        except:
            print(traceback.format_exc())

def bf_search(body, check_func):
    # print('Starting to minimize', body)
    if isinstance(body, dict):
        to_test = body.items()
        assemble = lambda l : dict(l)
    elif type(body) == list:
        to_test = zip(range(len(body)), body)
        assemble = lambda l: list(zip(*sorted(l))[1] if len(l) else [])
    #1. Test all sub-elements
    tested = []
    while len(to_test):
        current = to_test.pop()
        # print('Trying to eliminate', current)
        if not check_func(assemble(to_test+tested)):
            tested.append(current)
    #2. Recurse into remainig sub_items
    to_test = tested
    tested = []
    while len(to_test):
        key, value = to_test.pop()
        if isinstance(value,list) or isinstance(value, dict):
            def check_func_rec(body):
                return check_func(assemble(to_test + tested + [(key, body)]))
            value = bf_search(value, check_func_rec)
        tested.append((key, value))
    return assemble(tested)

def fix_content_length(headers, body):
    # headers = headers.split('\r\n')
    # for i in range(len(headers)):
    #     if headers[i].lower().startswith('content-length'):
    #         headers[i] = 'Content-Length: ' + str(len(body))
    print("Headers join : ", headers)
    return array.array('b', '\r\n'.join(str(headers)) + body)

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        callbacks.setExtensionName("Request minimizer")
        callbacks.registerContextMenuFactory(self)
        self._callbacks = callbacks

    def createMenuItems(self, invocation):
        if invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            return [JMenuItem(
                        "Minimize in current tab",
                        actionPerformed=partial(
                            Minimizer(self._callbacks, invocation.getSelectedMessages()).minimize,
                            True
                        )
                   ),
                    JMenuItem(
                        "Minimize in a new tab",
                        actionPerformed=partial(
                            Minimizer(self._callbacks, invocation.getSelectedMessages()).minimize,
                            False
                        )
                   ),
            ]

