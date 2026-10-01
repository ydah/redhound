const navigation = document.querySelector('.docs-navigation');
if (window.matchMedia('(max-width: 64rem)').matches) navigation.open = false;

const toc = document.querySelector('.page-toc');
for (const heading of document.querySelectorAll('.prose h2[id]')) {
  const item = document.createElement('li');
  const link = document.createElement('a');
  link.href = `#${heading.id}`;
  link.textContent = heading.textContent;
  item.append(link);
  toc.querySelector('ul').append(item);
  toc.hidden = false;
}
