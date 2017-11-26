import zlogger

m = 'HOLA'
d = {'nwk': 'abcd'}

o = zlogger.ZigbeeIDSLogger()
o.CreateLogHandlers()
o.MailHandler(m, d) 
