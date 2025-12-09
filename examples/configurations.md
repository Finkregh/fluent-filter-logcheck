# Configuration Examples

This document provides practical configuration examples for the fluent-plugin-logcheck filter.

## Basic Examples

### 1. Simple Systemd Log Filtering

Filter out routine systemd messages while keeping important events:

```xml
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

### 2. Application Log Noise Reduction

Reduce noise from application logs:

```xml
<filter app.rails.**>
  @type logcheck
  rules_dir /etc/logcheck/ignore.d.workstation/rails
  recursive_scan true
  match_field message
  default_action keep
  log_rule_errors false
</filter>
```

## Security Monitoring Examples

### 3. SSH Security Monitoring

Monitor SSH logs for security events:

```xml
<filter security.ssh>
  @type logcheck

  # Load SSH-specific security rules
  <rules>
    path /etc/logcheck/cracking.d/ssh
    type cracking
  </rules>

  <rules>
    path /etc/logcheck/violations.d/ssh
    type violations
  </rules>

  # Ignore routine SSH messages
  <rules>
    path /etc/logcheck/ignore.d.server/ssh
    type ignore
  </rules>

  # Enrich security alerts
  mark_matches true
  mark_field_prefix "ssh_security_"

  # Log all security events
  log_rule_errors true
  default_action keep
</filter>

# Route SSH security alerts
<match security.ssh>
  @type copy

  # Send to SIEM
  <store>
    @type forward
    <server>
      host siem.company.com
      port 24224
    </server>
  </store>

  # Store locally for analysis
  <store>
    @type file
    path /var/log/security/ssh-alerts
    <format>
      @type json
    </format>
  </store>
</match>
```

### 4. Web Server Security Monitoring

Monitor Apache/Nginx logs for attacks:

```xml
<filter web.access>
  @type logcheck

  # Web attack patterns
  <rules>
    path /etc/logcheck/cracking.d/apache
    type cracking
    recursive false
  </rules>

  <rules>
    path /etc/logcheck/cracking.d/nginx
    type cracking
    recursive false
  </rules>

  # Policy violations (e.g., blocked IPs)
  <rules>
    path /etc/logcheck/violations.d/web
    type violations
  </rules>

  # Filter out normal requests
  <rules>
    path /etc/logcheck/ignore.d.server/apache2
    type ignore
  </rules>

  # Custom rule priority (attacks first)
  rule_priority ["cracking", "violations", "ignore"]

  # Add detailed metadata
  mark_matches true
  mark_field_prefix "web_security_"

  # Performance tuning for high-volume logs
  cache_size 5000
  max_rules_per_file 2000
</filter>
```

## Advanced Configuration Examples

### 5. Multi-Service Environment

Complex environment with multiple services:

```xml
<filter **>
  @type logcheck

  # System-wide security rules (highest priority)
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

  # Service-specific ignore rules
  <rules>
    path /etc/logcheck/ignore.d.server
    type ignore
    recursive true
  </rules>

  <rules>
    path /etc/logcheck/ignore.d.workstation
    type ignore
    recursive true
  </rules>

  # Custom application rules
  <rules>
    path /opt/app/logcheck/ignore.d
    type ignore
    recursive true
  </rules>

  # Comprehensive monitoring
  mark_matches true
  mark_field_prefix "logcheck_"
  log_statistics true
  statistics_interval 300
  debug_mode false

  # Performance optimization
  cache_size 10000
  max_rules_per_file 1000
</filter>
```

### 6. Development Environment

Development setup with detailed debugging:

```xml
<filter dev.**>
  @type logcheck

  # Minimal security rules for development
  <rules>
    path /etc/logcheck/cracking.d/ssh
    type cracking
  </rules>

  # Development-specific ignore rules
  <rules>
    path /opt/dev/logcheck/ignore.d
    type ignore
    recursive true
  </rules>

  # Extensive debugging
  debug_mode true
  log_statistics true
  statistics_interval 60
  log_rule_errors true

  # Mark all matches for analysis
  mark_matches true
  mark_field_prefix "dev_logcheck_"

  # Keep everything by default
  default_action keep
</filter>
```

## Performance Tuning Examples

### 7. High-Volume Log Processing

Optimized for high-throughput environments:

```xml
<filter high-volume.**>
  @type logcheck

  # Essential rules only
  <rules>
    path /etc/logcheck/cracking.d/critical
    type cracking
  </rules>

  <rules>
    path /etc/logcheck/ignore.d.server/essential
    type ignore
  </rules>

  # Performance optimizations
  cache_size 20000
  max_rules_per_file 500
  ignore_parse_errors true

  # Minimal logging
  log_rule_errors false
  log_statistics true
  statistics_interval 600
  debug_mode false

  # Drop unmatched to reduce volume
  default_action drop
</filter>
```

### 8. Memory-Constrained Environment

Configuration for resource-limited systems:

```xml
<filter constrained.**>
  @type logcheck

  # Single essential rule file
  rules_file /etc/logcheck/ignore.d.server/essential

  # Minimal cache
  cache_size 100
  max_rules_per_file 100

  # Disable expensive features
  mark_matches false
  log_statistics false
  debug_mode false
  log_rule_errors false

  # Simple processing
  default_action keep
</filter>
```

## Custom Rule Examples

### 9. Application-Specific Rules

Custom rules for specific applications:

```xml
<filter app.myapp.**>
  @type logcheck

  # Application-specific rule directory
  <rules>
    path /opt/myapp/logcheck/rules
    type ignore
    recursive true
  </rules>

  # Custom rule priority
  rule_priority ["ignore"]

  # Application-specific field
  match_field log_message

  # Custom metadata prefix
  mark_matches true
  mark_field_prefix "myapp_"
</filter>
```

### 10. Multi-Field Matching

Using record transformation for complex matching:

```xml
# Pre-process to combine fields
<filter app.**>
  @type record_transformer
  <record>
    combined_message "${record['timestamp']} ${record['level']} ${record['message']}"
  </record>
</filter>

# Apply logcheck to combined field
<filter app.**>
  @type logcheck
  match_field combined_message
  rules_dir /etc/logcheck/app-rules
  mark_matches true
  mark_field_prefix "app_logcheck_"
</filter>
```

## Monitoring and Alerting Examples

### 11. Statistics and Monitoring

Configuration with comprehensive monitoring:

```xml
<filter monitored.**>
  @type logcheck

  rules_dir /etc/logcheck/ignore.d.server

  # Enable all monitoring features
  log_statistics true
  statistics_interval 60
  debug_mode false
  log_rule_errors true

  # Track performance
  mark_matches true
  mark_field_prefix "monitor_"
</filter>

# Send statistics to monitoring system
<match fluent.**>
  @type forward
  <server>
    host monitoring.company.com
    port 24224
  </server>
</match>
```

### 12. Error Handling and Recovery

Robust error handling configuration:

```xml
<filter robust.**>
  @type logcheck

  # Multiple rule sources with fallbacks
  <rules>
    path /etc/logcheck/primary/ignore.d
    type ignore
    recursive true
  </rules>

  <rules>
    path /etc/logcheck/backup/ignore.d
    type ignore
    recursive true
  </rules>

  # Graceful error handling
  ignore_parse_errors true
  log_rule_errors true

  # Conservative defaults
  default_action keep

  # Monitoring for issues
  debug_mode false
  log_statistics true
  statistics_interval 300
</filter>
```

## Testing Configurations

### 13. Test Environment Setup

Configuration for testing the plugin:

```xml
<source>
  @type dummy
  tag test.logcheck
  dummy {"message": "Test message for logcheck"}
  rate 1
</source>

<filter test.logcheck>
  @type logcheck

  # Test rules
  <rules>
    path ./test/fixtures/ignore.rules
    type ignore
  </rules>

  # Full debugging
  debug_mode true
  log_statistics true
  statistics_interval 10
  mark_matches true
  mark_field_prefix "test_"
</filter>

<match test.logcheck>
  @type stdout
</match>
```

## Best Practices

### Configuration Tips

1. **Start Simple**: Begin with basic configuration and add complexity gradually
2. **Test Rules**: Validate rule files before deploying to production
3. **Monitor Performance**: Use statistics logging to track plugin performance
4. **Security First**: Place security rules (cracking/violations) before ignore rules
5. **Resource Management**: Tune cache sizes and file limits based on your environment
6. **Error Handling**: Enable appropriate error logging for troubleshooting
7. **Documentation**: Document custom rules and configuration choices

### Performance Optimization

1. **Rule Organization**: Group related rules in the same files
2. **Cache Tuning**: Adjust cache sizes based on rule count and memory availability
3. **File Limits**: Set appropriate `max_rules_per_file` limits
4. **Selective Logging**: Disable verbose logging in production
5. **Rule Precedence**: Order rules by frequency of matches for better performance

### Security Considerations

1. **Rule Validation**: Regularly review and update rule files
2. **Access Control**: Secure rule file directories with appropriate permissions
3. **Alert Routing**: Ensure security alerts reach the appropriate teams
4. **Audit Logging**: Maintain logs of rule changes and plugin configuration
5. **Testing**: Test security rules with known attack patterns
