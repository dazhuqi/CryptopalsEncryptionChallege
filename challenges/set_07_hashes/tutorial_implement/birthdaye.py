from datetime import datetime, timedelta
import random

k = 23  # Change the value of k to observe the duplicates (if any)
X = 1000
jan_first = datetime(2022, 1, 1)
specific_birthday = jan_first.strftime("%m/%d/%Y")
print('Birthday that we want to find a collision for:',
      specific_birthday)


def generate_birthdays(group_size):
    jan_first = datetime(2022, 1, 1)
    birthday_list = [(jan_first + timedelta(days=random.randint(0,365))).
                     strftime("%m/%d/%Y") for i in range(group_size)]
    return sorted(birthday_list)


def shared_bday(group_size):
    duplicate = []
    birthdays = generate_birthdays(group_size)
    for a, birthdayA in enumerate(birthdays):
        if birthdayA == specific_birthday:
            return True


def generate_trials(group_size, trials):
    counts = []
    for i in range(trials):
        if shared_bday(group_size) == True:
            counts.append(1)
    return sum(counts) / trials


duplicate_prob = generate_trials(k, X)
print('The probability of duplicate birthday(s) for the given birthday: ', duplicate_prob)