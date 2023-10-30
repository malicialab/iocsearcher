# Copyright (c) MaliciaLab, 2023.
# This code is licensed under the MIT license. 
# See the LICENSE file in the iocsearcher project root for license terms. 
#
import json

# Base IOC class
class Ioc:
    def __init__(self, name, value, attributes=None):
        self.name = name
        self.value = value
        self.attributes = attributes if attributes is not None else {}

    def __len__(self):
        return len(self.value)

    def __eq__(self, other):
        return (self.name == other.name) and (self.value == other.value)

    def __lt__(self, other):
        if (self.name == other.name):
            return (self.value < other.value)
        else:
            return (self.name < other.name)

    def __hash__(self):
        return hash((self.name, self.value))

    def __unicode__(self):
        return (u"%s\t%s" % (self.name, self.value))

    def __repr__(self):
        return self.__unicode__()

    def add_attribute(self, name, value):
        self.attributes[name] = value

    def set_value(self, value):
        self.value = value

    def json(self):
        data = {
          'name' : self.name,
          'value' : self.value,
        }
        if len(self.attributes) > 0:
            data['attributes'] = self.attributes
        return json.dumps(data, sort_keys=True, default=str)


def create_ioc(name, value, attributes=None):
    """Create IOC from its name and value"""
    return Ioc(name, value, attributes=attributes)

