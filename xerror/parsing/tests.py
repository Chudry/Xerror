from django.test import TestCase

from .models import TextFile


class TextFileModelTest(TestCase):
    def setUp(self):
        TextFile.objects.create(name='Test')

    def test_str_repr(self):
        file = TextFile.objects.get(name='Test')
        self.assertEqual(str(file), file.name)


class IndexViewTest(TestCase):
    def setUp(self):
        TextFile.objects.create(name='Test')
        TextFile.objects.create(name='AnotherTest')

    def test_get(self):
        resp = self.client.get('/')
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp, 'index.html')

    def test_queryset(self):
        resp = self.client.get('/')
        queryset = TextFile.objects.all()
        self.assertTrue(queryset[0] in resp.context['files'])
        self.assertTrue(queryset[1] in resp.context['files'])

