class Test(object):
    def __init__(self, name, age):
        """

        """
        self.name = name
        self.ages = age

    def add_age(self, ages):
        print "ages:", ages
        print "self.ages:", self.ages
        ages[1] += 1
        print "ages:", ages
        print "self.ages:", self.ages
        # for age in ages:
        #     age += 1
        #     print "age:", age


test = Test("PP", {1: {1: 1}, 2: {2: 2}})
test.add_age(test.ages[1].copy())


def append_list(x):
    x.append(5)


def add_numb(x):
    x += 1


a = [1, 2, 3, 4]
b = [1, 2, 3, 4]
print"a:", a

append_list(a)
print "after append_list(a) a:", a

print"b:", b

add_numb(b[0])
print "after add_numb(b[0]):", b

def add(x):
    a=x[1]
    a+=1