#Nathan Todd
#Program: errors
#Exceptions that abort an exchange.


#Any rejected message: bad format, wrong session, invalid parameters.
class ProtocolError(Exception):
    pass


#A signature failed against the trusted key, or the signer has no trusted key.
class AuthenticationError(ProtocolError):
    pass
