json_rule = """
{
  "condition": {
    "link": null,
    "conditionType": "ConditionAndBlock",
    "isNegate": false,
    "children": [
      {
        "link": null,
        "conditionType": "ConditionAttributes",
        "isNegate": false,
        "dictionaryName": "LLDAP",
        "attributeName": "givenname",
        "operator": "equals",
        "dictionaryValue": null,
        "attributeValue": "{{ first_name }}"
      },
      {
        "link": null,
        "conditionType": "ConditionAttributes",
        "isNegate": false,
        "dictionaryName": "LLDAP",
        "attributeName": "sn",
        "operator": "equals",
        "dictionaryValue": null,
        "attributeValue": "{{ last_name }}"
      },
      {% if ip_addresses|length > 1 %}
      {
        "link": null,
        "conditionType": "ConditionOrBlock",
        "isNegate": false,
        "children": [
          {% for ip in ip_addresses %}
          {
            "link": null,
            "conditionType": "ConditionAttributes",
            "isNegate": false,
            "dictionaryName": "Network Access",
            "attributeName": "Device IP Address",
            "operator": "ipEquals",
            "dictionaryValue": null,
            "attributeValue": "{{ ip }}"
          }{% if not loop.last %},{% endif %}
          {% endfor %}
        ]
      }
      {% else %}
      {
        "link": null,
        "conditionType": "ConditionAttributes",
        "isNegate": false,
        "dictionaryName": "Network Access",
        "attributeName": "Device IP Address",
        "operator": "ipEquals",
        "dictionaryValue": null,
        "attributeValue": "{{ ip_addresses[0] }}"
      }
      {% endif %}
    ]
  },
  "default": false,
  "name": "{{ policy_name }}",
  "rank": 0,
  "state": "enabled"
}
"""
