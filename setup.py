from distutils.core import setup, Extension

uniformdh = Extension('uniformdh',
                      libraries=['ssl', 'crypto'],
                      sources=['uniformdh.c']);

setup(name = 'uniformdh',
       version = '0.0.1',
       description = 'OpenSSL based UniformDH',
       author = 'Yawning Angel',
       author_email = 'yawning@schwanenlied.me',
       url = 'https://github.com/Yawning/py-uniformdh',
       long_description = '''
OpenSSL based implementation of the obfs3/ScrambleSuit UniformDH handshake.
''',
       ext_modules = [uniformdh])
