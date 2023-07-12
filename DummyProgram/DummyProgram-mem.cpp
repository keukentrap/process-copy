#include<Windows.h>
#include<stdio.h>
#include<conio.h>

typedef char* node;

struct List {
	node elem;
	List* next;
};

List* list_tail(List* list) {
	while (list->next) {
		list = list->next;
	}
	return list;
}

node list_get(List* list, int index) {
	while (index > 0) {
		if (!list) {
			return 0;
		}
		list = list->next;
		index--;
	}
	return list->elem;
}

bool list_append(List* list, node elem) {
	auto tail = list_tail(list);
	tail->next = new struct List();
	if (!tail->next)
		return 0;
	tail->next->elem = elem;
	tail->next->next = 0;
	return 1;
}

bool list_insert(List* list, int index, node elem) {
	if (index < 0)
		return 0;

	while (index > 1) {
		if (!list)
			return 0;
		list = list->next;
		index--;
	}
	auto next = list->next;
	list->next = new struct List();
	list->next->elem = elem;
	list->next->next = next;
	return 1;
}

bool list_delete(List* list, int index) {
	if (index == 1) {
		struct List* next = list->next;
		struct List* nextnext = list->next->next;
		delete list->next;

		list->next = nextnext;
		return 1;
	}
	if (index > 1) {
		if (!list->next) {
			return 0;
		}
		return list_delete(list->next, --index);
	}
	if (index == 0)
		return 0;
}

struct List* list_generate(int n) {
	auto list = new List{};
	list->elem = new char[20] {};
	(list->elem)[0] = '0';
	for (int i = 1; i < n; i++) {
		auto buf = new char[20] {};
		sprintf_s(buf, 20, "%d", i);
		list_append(list, buf);
	}
	return list;
}

void list_print(List* list) {
	if (list) {
		printf("[ %3s", list->elem);
		list = list->next;
	}
	while (list) {
		printf(", %3s", list->elem);
		list = list->next;
	}
	printf(" ]\n");
}

struct tree {
	node elem;
	tree* left;
	tree* right;
};

int main()
{
	auto l = list_generate(500);
	auto m = new char[20];
	strncpy_s(m, 20, "FOO", 4);
	list_insert(l, 4, m);
	list_delete(l, 20);
	list_delete(l, 400);
	
	
	list_print(l);

	printf("4: %s\n", list_get(l, 4));
}
