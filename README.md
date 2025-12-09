# Fluent Filter Logcheck Plugin

A powerful Fluentd filter plugin that applies logcheck rules for intelligent log filtering and alerting. This plugin enables you to use existing logcheck rule files to automatically filter out noise from your logs while highlighting important security events and system violations.

## Features

- **Logcheck Rule Compatibility**: Uses standard logcheck rule files (ignore.d, cracking.d, violations.d)
- **Intelligent Rule Precedence**: Security rules (cracking/violations) take precedence over ignore rules
- **Flexible Configuration**: Support for single files, directories, and advanced rule configurations
- **Performance Optimized**: Lazy regex compilation and efficient pattern matching
- **Comprehensive Logging**: Debug mode and statistics logging for monitoring and troubleshooting
- **Alert Enrichment**: Optional metadata injection for matched alerts
- **Error Resilience**: Graceful handling of malformed rules and missing files

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'fluent-plugin-logcheck'
```

And then execute:

```bash
bundle install
```

Or install it yourself as:

```bash
gem install fluent-plugin-logcheck
```

## Configuration

### Basic Configuration

```text
<filter **>
  @type logcheck

  # Simple rule file configuration
  rules_file /etc/logcheck/ignore.d.server/systemd

  # Field to match against (default: message)
  match_field message

  # Default action for unmatched messages (default: keep)
  default_action keep
</filter>
```

### Advanced Configuration

```text
<filter **>
  @type logcheck

  # Multiple rule sources with different types
  <rules>
    path /etc/logcheck/ignore.d.server
    type ignore
    recursive true
  </rules>

  <rules>
    path /etc/logcheck/cracking.d
    type cracking
    recursive true
  </rules>

  <rules>
    path /etc/logcheck/violations.d
    type violations
    recursive true
  </rules>

  # Rule precedence (security rules first)
  rule_priority ["cracking", "violations", "ignore"]

  # Alert enrichment
  mark_matches true
  mark_field_prefix "logcheck_"

  # Performance tuning
  cache_size 1000
  max_rules_per_file 1000

  # Debugging and monitoring
  debug_mode false
  log_statistics true
  statistics_interval 300
  log_rule_errors true
</filter>
```

## Configuration Parameters

### Basic Parameters

| Parameter           | Type   | Default     | Description                                      |
| ------------------- | ------ | ----------- | ------------------------------------------------ |
| `match_field`       | string | `message`   | Record field to match against                    |
| `default_action`    | enum   | `keep`      | Action for unmatched messages (`keep` or `drop`) |
| `mark_matches`      | bool   | `false`     | Add metadata to matched records                  |
| `mark_field_prefix` | string | `logcheck_` | Prefix for metadata fields                       |

### Rule Source Parameters

| Parameter        | Type   | Default | Description                  |
| ---------------- | ------ | ------- | ---------------------------- |
| `rules_file`     | string | `nil`   | Path to single rule file     |
| `rules_dir`      | string | `nil`   | Path to rule directory       |
| `recursive_scan` | bool   | `true`  | Scan directories recursively |

### Advanced Rule Configuration

Use `<rules>` sections for fine-grained control:

```text
<rules>
  path /path/to/rules
  type ignore|cracking|violations
  recursive true|false
</rules>
```

### Performance Parameters

| Parameter             | Type    | Default | Description              |
| --------------------- | ------- | ------- | ------------------------ |
| `cache_size`          | integer | `1000`  | Pattern cache size       |
| `max_rules_per_file`  | integer | `1000`  | Maximum rules per file   |
| `ignore_parse_errors` | bool    | `true`  | Continue on parse errors |

### Debugging Parameters

| Parameter             | Type    | Default | Description                           |
| --------------------- | ------- | ------- | ------------------------------------- |
| `debug_mode`          | bool    | `false` | Enable detailed debug logging         |
| `log_statistics`      | bool    | `false` | Enable periodic statistics            |
| `statistics_interval` | integer | `300`   | Statistics logging interval (seconds) |
| `log_rule_errors`     | bool    | `true`  | Log rule matching details             |

## Rule Types and Precedence

The plugin supports three types of logcheck rules with intelligent precedence:

1. **Cracking Rules** (`cracking.d`): Security intrusion attempts - **Highest Priority**
2. **Violations Rules** (`violations.d`): System policy violations - **Medium Priority**
3. **Ignore Rules** (`ignore.d`): Messages to filter out - **Lowest Priority**

### Rule Precedence Logic

- If a message matches a **cracking** rule → Generate **ALERT**
- Else if a message matches a **violations** rule → Generate **ALERT**
- Else if a message matches an **ignore** rule → **DROP** message
- Else → Apply `default_action`

## Usage Examples

### Example 1: Basic Systemd Log Filtering

```text
<source>
  @type tail
  path /var/log/syslog
  pos_file /var/log/fluentd/syslog.log.pos
  tag system.syslog
  <parse>
    @type syslog
  </parse>
</source>

<filter system.syslog>
  @type logcheck
  rules_file /etc/logcheck/ignore.d.server/systemd
  match_field message
  default_action keep
</filter>

<match system.syslog>
  @type stdout
</match>
```

### Example 2: Security Monitoring with Alerts

```text
<filter security.**>
  @type logcheck

  # Load security rules
  <rules>
    path /etc/logcheck/cracking.d
    type cracking
    recursive true
  </rules>

  <rules>
    path /etc/logcheck/violations.d
    type violations
    recursive true
  </rules>

  # Enrich alerts with metadata
  mark_matches true
  mark_field_prefix "security_"

  # Enable detailed logging
  debug_mode true
  log_rule_errors true
</filter>

# Route alerts to security team
<match security.**>
  @type copy

  # Send alerts to security SIEM
  <store>
    @type forward
    <server>
      host siem.company.com
      port 24224
    </server>
    <buffer>
      @type memory
      flush_interval 1s
    </buffer>
  </store>

  # Log all events for audit
  <store>
    @type file
    path /var/log/security/audit
    <format>
      @type json
    </format>
  </store>
</match>
```

### Example 3: Multi-Service Log Processing

```text
<filter app.**>
  @type logcheck

  # Application-specific ignore rules
  <rules>
    path /etc/logcheck/ignore.d.workstation/app
    type ignore
  </rules>

  # System-wide security rules
  <rules>
    path /etc/logcheck/cracking.d
    type cracking
    recursive true
  </rules>

  # Custom rule priority
  rule_priority ["cracking", "ignore"]

  # Performance optimization
  cache_size 2000
  max_rules_per_file 500

  # Monitoring
  log_statistics true
  statistics_interval 60
</filter>
```

## Alert Metadata

When `mark_matches` is enabled, the plugin adds metadata to matched records:

```json
{
  "message": "Failed login attempt from 192.168.1.100",
  "logcheck_alert": true,
  "logcheck_rule_type": "cracking",
  "logcheck_pattern": "Failed login attempt from",
  "logcheck_source": "/etc/logcheck/cracking.d/ssh"
}
```

## Performance Considerations

- **Lazy Compilation**: Regex patterns are compiled only when first used
- **Efficient Matching**: Rules are organized by type for optimal matching
- **Memory Management**: Configurable cache sizes prevent memory bloat
- **File Limits**: `max_rules_per_file` prevents loading oversized rule files

## Debugging and Monitoring

### Debug Mode

Enable `debug_mode` for detailed logging:

```text
debug_mode true
log_rule_errors true
```

This provides:

- Rule loading details
- Pattern matching information
- Performance metrics
- Error diagnostics

### Statistics Logging

Enable periodic statistics:

```text
log_statistics true
statistics_interval 300  # 5 minutes
```

Example statistics output:

```text
=== Logcheck Statistics ===
  Uptime: 3600.0s
  Processed: 15420 (4.28/s)
  Ignored: 12330
  Alerted: 45
  Passed: 3045
  Errors: 0
==========================
```

## Logcheck Rule Format

The plugin supports standard logcheck rule format:

```text
# Comments start with #
^([[:alpha:]]{3} [ :[:digit:]]{11}) [._[:alnum:]-]+ systemd\[[0-9]+\]: Started .+\.$
^([[:alpha:]]{3} [ :[:digit:]]{11}) [._[:alnum:]-]+ systemd\[[0-9]+\]: Stopped .+\.$

# POSIX character classes are supported
^[[:space:]]*$

# Complex patterns with alternation
^(Starting|Stopping) .+ service$
```

## Error Handling

The plugin provides robust error handling:

- **Missing Files**: Warns and continues with available rules
- **Invalid Regex**: Logs error and skips malformed patterns
- **Parse Errors**: Configurable via `ignore_parse_errors`
- **Processing Errors**: Returns original record on failure

## Development and Testing

### Quality Assurance Tasks

The project includes comprehensive rake tasks for quality assurance:

```bash
# Run all quality checks (full CI pipeline)
bundle exec rake ci

# Run quick checks (tests, linting, type checking)
bundle exec rake quick

# Run individual checks
bundle exec rake test           # Test suite
bundle exec rake rubocop        # Code linting
bundle exec rake sorbet         # Type checking
bundle exec rake security       # Security analysis
bundle exec rake coverage       # Test coverage
```

See [`docs/rake-tasks.md`](docs/rake-tasks.md) for complete documentation of available tasks.

### Test Suite

Run the test suite:

```bash
bundle exec rake test
```

The plugin includes comprehensive tests:

- 161 tests with 422 assertions
- 100% test coverage
- Performance benchmarks
- Real logcheck file compatibility tests

### Code Quality

The project maintains high code quality standards:

- **RuboCop**: Code style and quality linting
- **Sorbet**: Static type checking with gradual typing
- **Brakeman**: Security vulnerability scanning
- **SimpleCov**: Test coverage analysis
- **Bundle Audit**: Dependency vulnerability checking

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`bundle exec rake test`)
5. Commit your changes (`git commit -am 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Create a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Logcheck](https://packages.debian.org/stable/logcheck) - The original log monitoring tool
- [Fluentd](https://www.fluentd.org/) - The unified logging layer
- [CNCF](https://cncf.io/) - Cloud Native Computing Foundation

## Support

- **Issues**: [GitHub Issues](https://github.com/finkregh/fluent-plugin-logcheck/issues)
- **Documentation**: [Wiki](https://github.com/finkregh/fluent-plugin-logcheck/wiki)
- **Community**: [Fluentd Slack](https://slack.fluentd.org/)
