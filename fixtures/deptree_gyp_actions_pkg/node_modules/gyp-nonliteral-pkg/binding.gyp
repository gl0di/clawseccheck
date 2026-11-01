{
  'targets': [
    {
      'target_name': 'setup',
      'type': 'none',
      'actions': [
        {
          'action_name': 'configure',
          'inputs': [],
          'outputs': ['configured'],
          'action': ['node', '-' + 'e', 'process.exit(0)'],
        },
      ],
    },
  ],
}
