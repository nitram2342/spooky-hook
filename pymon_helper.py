def GetSystemTimeAsFileTime(lpFileTime):
    _GetSystemTimeAsFileTime = windll.kernel32.GetSystemTimeAsFileTime
    _GetSystemTimeAsFileTime.argtypes = [kernel32.LPFILETIME]
    _GetSystemTimeAsFileTime.restype  = None
    _GetSystemTimeAsFileTime(lpFileTime)
