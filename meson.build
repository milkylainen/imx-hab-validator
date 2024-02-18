project('imx-hab-validator',
        'c',
        version: '0.1.0',
        default_options: [
                'warning_level=2',
                'werror=true',
        ],
)

if get_option('buildtype') == 'debug'
  add_project_arguments('-O1', language : 'c')
endif

openssl_dep = dependency('openssl')
incdir = include_directories('include')
executable('csf-validate-imx8',
        'src/csf-validate-imx8.c',
        dependencies: openssl_dep,
        include_directories: incdir
)
