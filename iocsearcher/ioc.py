# Copyright (c) MaliciaLab, 2023.
# This code is licensed under the MIT license. 
# See the LICENSE file in the iocsearcher project root for license terms. 
#
import json

class IocMatch:
    """A IOC as matched on text, prior to deduplication"""
    def __init__(self, name, start_offset, raw_value, rearmed_value,
                  normalized_value):
        self.name = name
        self.start_offset = start_offset
        self.raw_value = raw_value
        self.rearmed_value = rearmed_value
        self.value = normalized_value
        self.defanged = bool(raw_value != rearmed_value)

    def __len__(self):
        """The length is the the one of the raw_value"""
        return len(self.raw_value)

    def __eq__(self, other):
        """Two IocMatch considered the same if same start_offset and raw_value.
           They could still come from different texts
        """
        return ((self.start_offset == other.start_offset) and
                (self.raw_value == other.raw_value))

    def __lt__(self, other):
        """Compare IocMatch based on start_offset.
           If same start_offset, compare raw_value.
        """
        if (self.start_offset == other.start_offset):
            return (self.raw_value < other.raw_value)
        else:
            return (self.start_offset < other.start_offset)

    def __hash__(self):
        """IocMatch is uniquely identified by start_offset and raw_value"""
        return hash((self.start_offset, self.raw_value))

    def __unicode__(self):
        """Unicode texttual representation of IocMatch"""
        return (u"%s\t%s @ %d Raw: %s" % (self.name, self.value,
                                          self.start_offset, self.raw_value))

    def __repr__(self):
        """Textual representation of IocMatch"""
        return self.__unicode__()

    @property
    def ioc(self):
        """Return defanged and normalized Ioc"""
        return create_ioc(self.name, self.value)

    def json(self):
        """JSON representation of IocMatch"""
        data = {
          'start_offset' : self.start_offset,
          'name' : self.name,
          'value' : self.value,
          'raw_value' : self.raw_value,
          'rearmed_value' : self.rearmed_value,
        }
        return json.dumps(data, sort_keys=True, default=str)

    def defanged(self):
        """Returns whether IocMatch was defanged in the text"""
        return self.defanged

class Ioc:
    """An IOC after deduplication"""
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

