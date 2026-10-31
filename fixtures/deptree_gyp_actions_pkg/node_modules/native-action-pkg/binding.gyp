# Native addon build config (gyp: a Python literal, comments allowed).
{
  'variables': { 'lib_version%': '3.45.0' },
  'targets': [
    {
      'target_name': 'action_before_build',
      'type': 'none',
      'hard_dependency': 1,
      'actions': [
        {
          'action_name': 'unpack_dep',
          'inputs': ['./deps/lib-<@(lib_version).tar.gz'],
          'outputs': ['<(SHARED_INTERMEDIATE_DIR)/lib-<@(lib_version)/lib.c'],
          'action': ['node', './extract.js', './deps/lib-<@(lib_version).tar.gz', '<(SHARED_INTERMEDIATE_DIR)'],
        },
      ],
    },
    {
      'target_name': 'addon',
      'dependencies': ['action_before_build'],
      'sources': ['src/addon.cc'],
      'include_dirs': ["<!(node -p \"require('node-addon-api').include\")"],
    },
  ],
}
